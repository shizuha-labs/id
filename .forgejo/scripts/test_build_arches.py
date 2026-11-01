"""Tests for build_arches.py (arch-aware build selection + image/placement guards).

Pure stdlib; cluster I/O is driven through a fake ``kubectl`` binary that serves
JSON fixtures, so the CLI paths the workflows call are exercised end to end.
Run: python3 .forgejo/scripts/test_build_arches.py
"""
from __future__ import annotations

import contextlib
import copy
import importlib.util
import io
import json
import os
import stat
import sys
import tempfile
import textwrap
import unittest
from pathlib import Path

SCRIPT = Path(__file__).with_name("build_arches.py")
ROOT = SCRIPT.parents[2]
SPEC = importlib.util.spec_from_file_location("build_arches", SCRIPT)
assert SPEC and SPEC.loader
ba = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(ba)


# ── fixtures ─────────────────────────────────────────────────────────────────

def node(name, arch, *, ready=True, cordoned=False, taints=(), labels=None):
    lab = {"kubernetes.io/arch": arch, "kubernetes.io/hostname": name}
    lab.update(labels or {})
    return {
        "metadata": {"name": name, "labels": lab},
        "spec": {"unschedulable": cordoned, "taints": list(taints)},
        "status": {"conditions": [{"type": "Ready", "status": "True" if ready else "Unknown"}]},
    }


OPERATOR_HOLD = {"key": "operator", "value": "unschedulable", "effect": "NoSchedule"}
NOT_READY = {"key": "node.kubernetes.io/unreachable", "effect": "NoSchedule"}
CONTROL_PLANE = {"node-role.kubernetes.io/control-plane": "true"}


def build_job(arch):
    """The scheduling-relevant shape of the workflows' rendered kaniko Job."""
    return {
        "apiVersion": "batch/v1", "kind": "Job",
        "metadata": {"name": f"ci-build-x-deadbee-{arch}"},
        "spec": {"template": {"spec": {
            "nodeSelector": {"kubernetes.io/arch": arch},
            "tolerations": [
                {"key": "node.shizuha/workstation", "operator": "Exists", "effect": "NoSchedule"},
                {"key": "shizuha.com/inference-paused", "operator": "Exists", "effect": "NoSchedule"},
                {"key": "operator", "operator": "Equal", "value": "unschedulable", "effect": "NoSchedule"},
            ],
            "affinity": {"nodeAffinity": {"requiredDuringSchedulingIgnoredDuringExecution": {
                "nodeSelectorTerms": [{"matchExpressions": [
                    {"key": "node-role.kubernetes.io/control-plane", "operator": "DoesNotExist"},
                    {"key": "kubernetes.io/hostname", "operator": "NotIn", "values": ["i9-ws"]},
                ]}],
            }}},
        }}},
    }


# Live Jaipur shape on 2026-11-01: every amd64 node NotReady (alienware-1 also
# cordoned); arm64 gx10 workers Ready; gx10-5 is a control-plane node.
JAIPUR_NOW = [
    node("s1", "amd64", ready=False, taints=[OPERATOR_HOLD, NOT_READY]),
    node("i9-ws", "amd64", ready=False, taints=[NOT_READY]),
    node("alienware-1", "amd64", ready=False, cordoned=True, taints=[NOT_READY]),
    node("gx10-5", "arm64", labels=CONTROL_PLANE),
    node("gx10-1", "arm64"),
    node("gx10-2", "arm64"),
]


def candidates():
    return {a: ba.pod_spec_of(build_job(a)) for a in ("amd64", "arm64")}


# ── selection predicates ─────────────────────────────────────────────────────

class SelectionTests(unittest.TestCase):
    def test_amd64_outage_builds_arm64_only(self):
        selected, eligible = ba.select_arches(candidates(), JAIPUR_NOW)
        self.assertEqual(selected, ["arm64"])
        self.assertEqual(eligible["arm64"], ["gx10-1", "gx10-2"])  # control plane excluded
        self.assertEqual(eligible["amd64"], [])

    def test_returns_to_multiarch_when_s1_recovers(self):
        nodes = copy.deepcopy(JAIPUR_NOW)
        nodes[0] = node("s1", "amd64", taints=[OPERATOR_HOLD])  # tolerated operator hold
        selected, eligible = ba.select_arches(candidates(), nodes)
        self.assertEqual(selected, ["amd64", "arm64"])
        self.assertEqual(eligible["amd64"], ["s1"])

    def test_ready_amd64_excluded_by_affinity_is_not_admissible(self):
        nodes = JAIPUR_NOW + [node("i9-ws", "amd64")]  # Ready, but hostname NotIn [i9-ws]
        self.assertEqual(ba.select_arches(candidates(), nodes)[0], ["arm64"])

    def test_cordoned_or_untolerated_taint_is_not_admissible(self):
        for n in (
            node("alienware-1", "amd64", cordoned=True),
            node("alienware-1", "amd64", taints=[{"key": "gpu", "value": "x", "effect": "NoSchedule"}]),
            node("alienware-1", "amd64", taints=[{"key": "drain", "effect": "NoExecute"}]),
        ):
            with self.subTest(node=n["spec"]):
                self.assertEqual(ba.select_arches(candidates(), [n, node("gx10-1", "arm64")])[0], ["arm64"])

    def test_prefer_no_schedule_taint_does_not_block(self):
        n = node("alienware-1", "amd64", taints=[{"key": "soft", "effect": "PreferNoSchedule"}])
        self.assertEqual(ba.select_arches(candidates(), [n, node("gx10-1", "arm64")])[0], ["amd64", "arm64"])

    def test_only_control_plane_arm64_means_no_arm64(self):
        nodes = [node("gx10-5", "arm64", labels=CONTROL_PLANE), node("s1", "amd64")]
        self.assertEqual(ba.select_arches(candidates(), nodes)[0], ["amd64"])

    def test_toleration_semantics(self):
        taint = {"key": "k", "value": "v", "effect": "NoSchedule"}
        self.assertTrue(ba._tolerates({"operator": "Exists"}, taint))  # wildcard
        self.assertFalse(ba._tolerates({"key": "", "operator": "Equal"}, taint))
        self.assertTrue(ba._tolerates({"key": "k", "operator": "Exists"}, taint))
        self.assertTrue(ba._tolerates({"key": "k", "value": "v"}, taint))  # default Equal
        self.assertFalse(ba._tolerates({"key": "k", "value": "w"}, taint))
        self.assertFalse(ba._tolerates({"key": "k", "operator": "Exists", "effect": "NoExecute"}, taint))
        self.assertFalse(ba._tolerates({"key": "other", "operator": "Exists"}, taint))

    def test_affinity_operators_and_terms(self):
        n = node("n1", "amd64", labels={"cpu": "16", "zone": "a"})
        def spec(*exprs, fields=()):
            return {"affinity": {"nodeAffinity": {"requiredDuringSchedulingIgnoredDuringExecution": {
                "nodeSelectorTerms": [{"matchExpressions": list(exprs), "matchFields": list(fields)}]}}}}
        self.assertTrue(ba.affinity_matches(spec({"key": "cpu", "operator": "Gt", "values": ["8"]}), n))
        self.assertFalse(ba.affinity_matches(spec({"key": "cpu", "operator": "Lt", "values": ["8"]}), n))
        self.assertFalse(ba.affinity_matches(spec({"key": "missing", "operator": "Gt", "values": ["1"]}), n))
        self.assertTrue(ba.affinity_matches(spec({"key": "zone", "operator": "In", "values": ["a", "b"]}), n))
        self.assertTrue(ba.affinity_matches(spec({"key": "missing", "operator": "NotIn", "values": ["a"]}), n))
        self.assertFalse(ba.affinity_matches(spec({"key": "zone", "operator": "Bogus"}), n))
        self.assertTrue(ba.affinity_matches(spec(fields=[{"key": "metadata.name", "operator": "In", "values": ["n1"]}]), n))
        self.assertFalse(ba.affinity_matches(spec(), n))  # empty term matches nothing
        self.assertFalse(ba.affinity_matches(
            {"affinity": {"nodeAffinity": {"requiredDuringSchedulingIgnoredDuringExecution": {"nodeSelectorTerms": []}}}}, n))
        self.assertFalse(ba.affinity_matches({"nodeSelector": {"kubernetes.io/arch": "arm64"}}, n))
        self.assertTrue(ba.affinity_matches({}, n))
        # OR across terms
        two = {"affinity": {"nodeAffinity": {"requiredDuringSchedulingIgnoredDuringExecution": {"nodeSelectorTerms": [
            {"matchExpressions": [{"key": "zone", "operator": "In", "values": ["z"]}]},
            {"matchExpressions": [{"key": "zone", "operator": "In", "values": ["a"]}]},
        ]}}}}
        self.assertTrue(ba.affinity_matches(two, n))

    def test_parse_arch_list(self):
        self.assertEqual(ba.parse_arch_list("linux/amd64, linux/arm64"), ["amd64", "arm64"])
        self.assertEqual(ba.parse_arch_list("arm64 arm64"), ["arm64"])
        self.assertEqual(ba.parse_arch_list(""), [])


# ── fake kubectl harness ─────────────────────────────────────────────────────

FAKE_KUBECTL = textwrap.dedent(r'''
    #!/usr/bin/env python3
    import json, os, sys
    d = os.environ["FAKE_KUBE_DIR"]
    args = sys.argv[1:]
    with open(os.path.join(d, "calls.log"), "a") as fh:
        fh.write(json.dumps(args) + "\n")
    def out(name):
        sys.stdout.write(open(os.path.join(d, name)).read()); sys.exit(0)
    if args[:2] == ["get", "nodes"]:
        out("nodes.json")
    if args[:2] == ["get", "deployment"]:
        path = os.path.join(d, f"deploy-{args[4]}-{args[2]}.json")
        if not os.path.exists(path):
            sys.stderr.write(f'Error from server (NotFound): deployments.apps "{args[2]}" not found\n'); sys.exit(1)
        out(os.path.basename(path))
    if args[:2] == ["get", "pods"]:
        out(f"pods-{args[3]}.json")
    if args[:1] == ["delete"]:
        sys.exit(0)
    if args[:1] == ["apply"]:
        open(os.path.join(d, "applied.json"), "w").write(sys.stdin.read()); sys.exit(0)
    if args[:1] == ["get"] and args[1].startswith("job/"):
        out("job.json")
    if args[:1] == ["logs"]:
        out("job.log")
    sys.stderr.write("unexpected kubectl " + " ".join(args) + "\n"); sys.exit(97)
''').lstrip()


class FakeCluster:
    def __init__(self):
        self._tmp = tempfile.TemporaryDirectory()
        self.dir = Path(self._tmp.name)
        exe = self.dir / "kubectl"
        exe.write_text(FAKE_KUBECTL.replace("/usr/bin/env python3", sys.executable, 1))
        exe.chmod(exe.stat().st_mode | stat.S_IXUSR)
        self.env = {"KUBECTL": str(exe), "FAKE_KUBE_DIR": str(self.dir)}

    def write(self, name, value):
        (self.dir / name).write_text(value if isinstance(value, str) else json.dumps(value))

    def calls(self):
        log = self.dir / "calls.log"
        return [json.loads(line) for line in log.read_text().splitlines()] if log.exists() else []

    def run(self, *argv):
        buf = io.StringIO()
        old = {k: os.environ.get(k) for k in self.env}
        os.environ.update(self.env)
        try:
            with contextlib.redirect_stdout(buf):
                rc = ba.main(list(argv))
        finally:
            for k, v in old.items():
                if v is None:
                    os.environ.pop(k, None)
                else:
                    os.environ[k] = v
        return rc, buf.getvalue()

    def close(self):
        self._tmp.cleanup()


class SelectCliTests(unittest.TestCase):
    def setUp(self):
        self.k = FakeCluster()
        self.addCleanup(self.k.close)
        for arch in ("amd64", "arm64"):
            self.k.write(f"job-{arch}.json", build_job(arch))
        self.out = self.k.dir / "arches.txt"

    def select(self, nodes):
        self.k.write("nodes.json", {"items": nodes})
        return self.k.run(
            "select", "--candidate", f"amd64={self.k.dir / 'job-amd64.json'}",
            "--candidate", f"arm64={self.k.dir / 'job-arm64.json'}",
            "--require", "arm64", "--output", str(self.out),
        )

    def test_outage_selects_arm64_and_warns_naming_amd64(self):
        rc, out = self.select(JAIPUR_NOW)
        self.assertEqual(rc, 0, out)
        self.assertEqual(self.out.read_text(), "arm64\n")
        warning = next(line for line in out.splitlines() if line.startswith("::warning::"))
        self.assertIn("building WITHOUT amd64", warning)
        for detail in ("s1=not-ready", "i9-ws=not-ready", "alienware-1=not-ready"):
            self.assertIn(detail, warning)
        self.assertIn("build-arches=arm64", out)

    def test_healthy_cluster_builds_both_without_warning(self):
        rc, out = self.select([node("s1", "amd64", taints=[OPERATOR_HOLD]), node("gx10-1", "arm64")])
        self.assertEqual(rc, 0, out)
        self.assertEqual(self.out.read_text(), "amd64 arm64\n")
        self.assertNotIn("::warning::", out)

    def test_missing_arm64_fails_closed(self):
        rc, out = self.select([node("s1", "amd64"), node("gx10-1", "arm64", ready=False)])
        self.assertEqual(rc, 1)
        self.assertIn("::error::required build architecture arm64", out)
        self.assertIn("gx10-1=not-ready", out)
        self.assertFalse(self.out.exists())

    def test_required_arch_needs_a_candidate(self):
        self.k.write("nodes.json", {"items": JAIPUR_NOW})
        rc, out = self.k.run("select", "--candidate", f"amd64={self.k.dir / 'job-amd64.json'}",
                             "--require", "arm64", "--output", str(self.out))
        self.assertEqual(rc, 1)
        self.assertIn("no --candidate", out)


def pod(name, node_name, *, phase="Running", deleting=False):
    meta = {"name": name}
    if deleting:
        meta["deletionTimestamp"] = "2026-10-28T10:46:29Z"
    return {"metadata": meta, "spec": {"nodeName": node_name} if node_name else {}, "status": {"phase": phase}}


class PlacementTests(unittest.TestCase):
    def setUp(self):
        self.k = FakeCluster()
        self.addCleanup(self.k.close)
        self.k.write("nodes.json", {"items": JAIPUR_NOW + [node("gx10-9", "arm64")]})
        self.k.write("deploy-shizuha-shizuha-id.json", {"spec": {"selector": {"matchLabels": {
            "app.kubernetes.io/name": "shizuha-id", "app.kubernetes.io/component": "backend"}}}})

    def test_live_pod_arches_ignores_terminating_finished_and_unbound(self):
        pods = [
            pod("a", "gx10-1"), pod("b", "i9-ws", phase="Pending", deleting=True),
            pod("c", "gx10-2", phase="Succeeded"), pod("d", None, phase="Pending"),
            pod("e", "s1", phase="Failed"),
        ]
        self.assertEqual(ba.live_pod_arches(pods, JAIPUR_NOW), {"arm64": ["a@gx10-1"]})

    def test_arm64_image_ok_when_only_stale_pods_remain_on_amd64(self):
        # Mirrors live shizuha-id: a deleting pod is stranded on NotReady i9-ws.
        self.k.write("pods-shizuha.json", {"items": [
            pod("id-1", "gx10-1"), pod("id-2", "gx10-9"), pod("id-3", "i9-ws", phase="Pending", deleting=True),
        ]})
        rc, out = self.k.run("check-placement", "--platforms", "arm64", "--deployment", "shizuha/shizuha-id")
        self.assertEqual(rc, 0, out)
        self.assertIn("placement-check shizuha/shizuha-id: OK", out)
        selector = next(c for c in self.k.calls() if c[:2] == ["get", "pods"])[5]
        self.assertEqual(selector, "app.kubernetes.io/component=backend,app.kubernetes.io/name=shizuha-id")

    def test_refuses_arm64_only_image_while_a_live_pod_runs_on_amd64(self):
        self.k.write("pods-shizuha.json", {"items": [pod("id-1", "gx10-1"), pod("id-2", "s1")]})
        rc, out = self.k.run("check-placement", "--platforms", "linux/arm64", "--deployment", "shizuha/shizuha-id")
        self.assertEqual(rc, 1)
        self.assertIn("::error::refusing rollout", out)
        self.assertIn("id-2@s1", out)
        rc, out = self.k.run("check-placement", "--platforms", "linux/amd64,linux/arm64",
                             "--deployment", "shizuha/shizuha-id")
        self.assertEqual(rc, 0, out)

    def test_absent_deployment_is_first_install(self):
        rc, out = self.k.run("check-placement", "--platforms", "arm64", "--deployment", "shizuha/new-svc")
        self.assertEqual(rc, 0, out)
        self.assertIn("deployment absent", out)

    def test_empty_platforms_and_selectors_fail_closed(self):
        rc, out = self.k.run("check-placement", "--platforms", " ", "--deployment", "shizuha/shizuha-id")
        self.assertEqual(rc, 1)
        with self.assertRaises(ba.GuardError):
            ba.label_selector({})
        self.assertEqual(
            ba.label_selector({"matchLabels": {"a": "1"}, "matchExpressions": [
                {"key": "b", "operator": "In", "values": ["x", "y"]}, {"key": "c", "operator": "Exists"},
                {"key": "d", "operator": "DoesNotExist"}, {"key": "e", "operator": "NotIn", "values": ["z"]}]}),
            "a=1,b in (x,y),c,!d,e notin (z)",
        )


class ManifestPlatformsTests(unittest.TestCase):
    def setUp(self):
        self.k = FakeCluster()
        self.addCleanup(self.k.close)
        self.k.write("job.json", {"status": {"succeeded": 1, "conditions": [{"type": "Complete", "status": "True"}]}})
        self.out = self.k.dir / "platforms.txt"

    def run_cli(self, *extra):
        return self.k.run(
            "manifest-platforms", "--registry", "registry.example:5000", "--repo", "shizuha-id",
            "--tag", "id-deadbee", "--job-name", "ci-verify-shizuha-id-deadbee",
            "--label", "service=id", "--poll-seconds", "0", "--output", str(self.out), *extra,
        )

    def test_single_arch_index_matches_single_arch_build(self):
        self.k.write("job.log", 'noise\nSHIZUHA_IMAGE_PLATFORMS=["linux/arm64"]\n')
        rc, out = self.run_cli("--expect", "arm64")
        self.assertEqual(rc, 0, out)
        self.assertEqual(self.out.read_text(), "arm64\n")
        job = json.loads((self.k.dir / "applied.json").read_text())
        self.assertEqual(job["metadata"]["labels"], {"app": "ci-verify", "service": "id"})
        self.assertEqual(job["spec"]["ttlSecondsAfterFinished"], 300)
        self.assertEqual(job["spec"]["activeDeadlineSeconds"], 180)
        script = job["spec"]["template"]["spec"]["containers"][0]["command"][2]
        self.assertIn("http://registry.example:5000/v2/shizuha-id/manifests/id-deadbee", script)
        compile(script, "manifest-check", "exec")  # the in-cluster script is valid Python

    def test_index_must_equal_the_built_set(self):
        self.k.write("job.log", 'SHIZUHA_IMAGE_PLATFORMS=["linux/arm64"]\n')
        rc, out = self.run_cli("--expect", "amd64 arm64")
        self.assertEqual(rc, 1)
        self.assertIn("!= built ['linux/amd64', 'linux/arm64']", out)
        self.k.write("job.log", 'SHIZUHA_IMAGE_PLATFORMS=["linux/amd64", "linux/arm64"]\n')
        rc, out = self.run_cli("--expect", "arm64")
        self.assertEqual(rc, 1)
        self.k.write("job.log", 'SHIZUHA_IMAGE_PLATFORMS=["linux/amd64", "linux/arm64"]\n')
        rc, out = self.run_cli("--expect", "amd64 arm64")
        self.assertEqual(rc, 0, out)
        self.assertEqual(self.out.read_text(), "amd64 arm64\n")

    def test_failed_or_silent_job_fails(self):
        self.k.write("job.log", "boom\n")
        self.k.write("job.json", {"status": {"failed": 1}})
        rc, out = self.run_cli()
        self.assertEqual(rc, 1)
        self.assertIn("failed", out)
        self.k.write("job.json", {"status": {"succeeded": 1}})
        rc, out = self.run_cli()
        self.assertEqual(rc, 1)
        self.assertIn("printed no platform list", out)


# ── workflow contract: the deploy workflows actually use the helper ──────────

WORKFLOWS = {
    name: ROOT / ".forgejo/workflows" / name
    for name in ("deploy.yml", "deploy-frontend.yml")
    if (ROOT / ".forgejo/workflows" / name).exists()
}


class WorkflowContractTests(unittest.TestCase):
    def test_helper_is_byte_identical_contract_header(self):
        self.assertIn("Byte-identical in the id and mail repositories", SCRIPT.read_text())

    def test_build_set_comes_from_the_cluster_not_a_literal_pair(self):
        for name, path in WORKFLOWS.items():
            text = path.read_text()
            with self.subTest(workflow=name):
                self.assertNotIn("preflight --arch amd64 --arch arm64", text)
                self.assertNotIn("wait-pair", text)
                self.assertIn("python3 .forgejo/scripts/test_build_arches.py", text)
                self.assertIn(".forgejo/scripts/build_arches.py select", text)
                self.assertIn("--require arm64", text)
                self.assertIn('read -r -a BUILD_ARCHES', text)
                self.assertIn('"$BUILD_GUARD" wait-jobs', text)
                self.assertIn(".forgejo/scripts/build_arches.py manifest-platforms", text)
                self.assertIn('--expect "${BUILD_ARCHES[*]}"', text)
                # crane appends exactly the built per-arch images
                self.assertIn('for ARCH in "${BUILD_ARCHES[@]}"', text)
                self.assertNotIn("missing required platform(s)", text)

    def test_rollout_is_guarded_by_live_pod_placement_before_promotion(self):
        for name, path in WORKFLOWS.items():
            text = path.read_text()
            with self.subTest(workflow=name):
                guard = text.index(".forgejo/scripts/build_arches.py check-placement")
                promote = text.index("VALS_URL=")
                self.assertLess(guard, promote, "placement guard must run before the chart tag is promoted")


if __name__ == "__main__":
    unittest.main(verbosity=2)

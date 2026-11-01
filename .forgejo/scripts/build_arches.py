#!/usr/bin/env python3
"""Architecture-aware build selection and image/placement guards.

Byte-identical in the id and mail repositories (deploy.yml + deploy-frontend.yml).

Why: the multi-arch deploy workflows used to require BOTH an amd64 and an
arm64 kaniko Job. When every amd64 node is NotReady/cordoned (Jaipur,
2026-10-28..) no release could complete, although every production pod runs
on arm64. Instead of a hard-coded arch list this helper derives the build set
from the cluster each run:

  select              arches that have >=1 node which is Ready, not cordoned,
                      and admits the *rendered* build Job (nodeSelector,
                      required nodeAffinity, NoSchedule/NoExecute taints vs
                      tolerations). Required arches (arm64) fail closed;
                      skipped optional arches are reported as ::warning::.
                      As soon as an amd64 node is admissible again the build
                      returns to multi-arch automatically.
  manifest-platforms  reads the pushed image index through an in-cluster Job
                      (the registry ClusterIP is reachable from build pods)
                      and, with --expect, requires the exact platform set.
  check-placement     refuses a rollout whose image platforms do not cover the
                      architecture of every node currently running (not
                      terminating) pods of the target Deployments.

Stdlib only; all cluster I/O goes through ``$KUBECTL`` (default ``kubectl``)
so tests drive it with a fake binary.
"""
from __future__ import annotations

import argparse
import json
import os
import subprocess
import sys
import time
from pathlib import Path
from typing import Any, Iterable

ARCH_LABEL = "kubernetes.io/arch"
CANDIDATE_ORDER = ("amd64", "arm64")
BLOCKING_TAINT_EFFECTS = {"NoSchedule", "NoExecute"}
LIVE_POD_PHASES = {"Pending", "Running", "Unknown"}
PLATFORMS_PREFIX = "SHIZUHA_IMAGE_PLATFORMS="


class GuardError(RuntimeError):
    pass


# ── kubectl ──────────────────────────────────────────────────────────────────

def kubectl(*args: str, stdin: str | None = None, check: bool = True) -> subprocess.CompletedProcess[str]:
    proc = subprocess.run(
        [os.environ.get("KUBECTL", "kubectl"), *args],
        input=stdin,
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        check=False,
    )
    if check and proc.returncode:
        raise GuardError(f"kubectl {' '.join(args[:3])} failed: {proc.stderr.strip() or proc.stdout.strip()}")
    return proc


def kube_json(*args: str) -> dict[str, Any]:
    return json.loads(kubectl(*args, "-o", "json").stdout)


# ── scheduling predicates (subset of kube-scheduler filters we rely on) ──────

def _labels(node: dict[str, Any]) -> dict[str, str]:
    return node.get("metadata", {}).get("labels", {}) or {}


def node_ready(node: dict[str, Any]) -> bool:
    for cond in node.get("status", {}).get("conditions", []) or []:
        if cond.get("type") == "Ready":
            return cond.get("status") == "True"
    return False


def _expression_matches(expr: dict[str, Any], labels: dict[str, str]) -> bool:
    key, op = expr.get("key", ""), expr.get("operator", "")
    values = expr.get("values", []) or []
    present = key in labels
    if op == "In":
        return present and labels[key] in values
    if op == "NotIn":
        return not present or labels[key] not in values
    if op == "Exists":
        return present
    if op == "DoesNotExist":
        return not present
    if op in ("Gt", "Lt"):
        if not present or len(values) != 1:
            return False
        try:
            left, right = int(labels[key]), int(values[0])
        except ValueError:
            return False
        return left > right if op == "Gt" else left < right
    return False  # unknown operator: never match (fail closed)


def _term_matches(term: dict[str, Any], node: dict[str, Any]) -> bool:
    exprs = term.get("matchExpressions", []) or []
    fields = term.get("matchFields", []) or []
    if not exprs and not fields:
        return False  # an empty term matches no objects (k8s semantics)
    labels = _labels(node)
    if not all(_expression_matches(e, labels) for e in exprs):
        return False
    name_fields = {"metadata.name": node.get("metadata", {}).get("name", "")}
    return all(_expression_matches(f, name_fields) for f in fields)


def affinity_matches(pod_spec: dict[str, Any], node: dict[str, Any]) -> bool:
    selector = pod_spec.get("nodeSelector", {}) or {}
    labels = _labels(node)
    if any(labels.get(k) != v for k, v in selector.items()):
        return False
    required = (
        (pod_spec.get("affinity") or {}).get("nodeAffinity", {}) or {}
    ).get("requiredDuringSchedulingIgnoredDuringExecution")
    if required is None:
        return True
    terms = required.get("nodeSelectorTerms", []) or []
    return any(_term_matches(term, node) for term in terms)


def _tolerates(toleration: dict[str, Any], taint: dict[str, Any]) -> bool:
    effect = toleration.get("effect", "")
    if effect and effect != taint.get("effect"):
        return False
    key = toleration.get("key", "")
    operator = toleration.get("operator", "Equal")
    if not key:
        return operator == "Exists"
    if key != taint.get("key"):
        return False
    if operator == "Exists":
        return True
    return toleration.get("value", "") == taint.get("value", "")


def untolerated_taints(pod_spec: dict[str, Any], node: dict[str, Any]) -> list[str]:
    tolerations = pod_spec.get("tolerations", []) or []
    blocked = []
    for taint in node.get("spec", {}).get("taints", []) or []:
        if taint.get("effect") not in BLOCKING_TAINT_EFFECTS:
            continue
        if not any(_tolerates(t, taint) for t in tolerations):
            blocked.append(f"{taint.get('key')}={taint.get('value', '')}:{taint.get('effect')}")
    return blocked


def node_rejection(pod_spec: dict[str, Any], node: dict[str, Any]) -> str | None:
    """None when the node can run the pod now, else a short reason."""
    if not node_ready(node):
        return "not-ready"
    if node.get("spec", {}).get("unschedulable"):
        return "cordoned"
    if not affinity_matches(pod_spec, node):
        return "affinity"
    blocked = untolerated_taints(pod_spec, node)
    if blocked:
        return "taint:" + ",".join(blocked)
    return None


def pod_spec_of(obj: dict[str, Any]) -> dict[str, Any]:
    """Pod spec from a rendered Job/Deployment (template) or a bare Pod."""
    spec = obj.get("spec", {}) or {}
    template = spec.get("template")
    if isinstance(template, dict):
        return template.get("spec", {}) or {}
    return spec


def select_arches(
    candidates: dict[str, dict[str, Any]],
    nodes: Iterable[dict[str, Any]],
) -> tuple[list[str], dict[str, list[str]]]:
    """Return (selected arches in canonical order, admissible node names by arch).

    ``candidates`` maps arch -> pod spec of the build Job rendered for it.
    """
    nodes = list(nodes)
    eligible = {
        arch: sorted(
            n.get("metadata", {}).get("name", "<unknown>")
            for n in nodes
            if _labels(n).get(ARCH_LABEL) == arch and node_rejection(pod_spec, n) is None
        )
        for arch, pod_spec in candidates.items()
    }
    order = [a for a in CANDIDATE_ORDER if a in candidates] + sorted(set(candidates) - set(CANDIDATE_ORDER))
    return [a for a in order if eligible[a]], eligible


# ── placement guard ──────────────────────────────────────────────────────────

def live_pod_arches(pods: Iterable[dict[str, Any]], nodes: Iterable[dict[str, Any]]) -> dict[str, list[str]]:
    """arch -> ["pod@node", ...] for pods that are bound and not terminating."""
    node_arch = {n.get("metadata", {}).get("name"): _labels(n).get(ARCH_LABEL, "unknown") for n in nodes}
    out: dict[str, list[str]] = {}
    for pod in pods:
        meta, spec, status = pod.get("metadata", {}), pod.get("spec", {}), pod.get("status", {})
        node = spec.get("nodeName")
        if not node or meta.get("deletionTimestamp") or status.get("phase") not in LIVE_POD_PHASES:
            continue
        arch = node_arch.get(node, "unknown")
        out.setdefault(arch, []).append(f"{meta.get('name')}@{node}")
    return out


def label_selector(selector: dict[str, Any]) -> str:
    parts = [f"{k}={v}" for k, v in sorted((selector.get("matchLabels") or {}).items())]
    for expr in selector.get("matchExpressions", []) or []:
        key, op, values = expr["key"], expr["operator"], expr.get("values", []) or []
        if op == "In":
            parts.append(f"{key} in ({','.join(values)})")
        elif op == "NotIn":
            parts.append(f"{key} notin ({','.join(values)})")
        elif op == "Exists":
            parts.append(key)
        elif op == "DoesNotExist":
            parts.append(f"!{key}")
        else:
            raise GuardError(f"unsupported selector operator {op}")
    if not parts:
        raise GuardError("refusing an empty Deployment selector (would match every pod)")
    return ",".join(parts)


def parse_arch_list(value: str) -> list[str]:
    arches = []
    for item in value.replace(",", " ").split():
        arch = item.split("/")[-1].strip()  # accept linux/arm64 or arm64
        if arch and arch not in arches:
            arches.append(arch)
    return arches


# ── commands ─────────────────────────────────────────────────────────────────

def cmd_select(args: argparse.Namespace) -> int:
    candidates: dict[str, dict[str, Any]] = {}
    for item in args.candidate:
        arch, _, path = item.partition("=")
        if not arch or not path:
            raise GuardError(f"--candidate expects ARCH=RENDERED_JOB.json, got {item!r}")
        candidates[arch] = pod_spec_of(json.loads(Path(path).read_text()))
    nodes = (json.loads(Path(args.nodes).read_text()) if args.nodes else kube_json("get", "nodes")).get("items", [])
    unknown = [a for a in args.require if a not in candidates]
    if unknown:
        raise GuardError(f"required arch(es) {unknown} have no --candidate build Job")
    selected, eligible = select_arches(candidates, nodes)
    for arch in selected:
        print(f"build-arch-select arch={arch} eligible={','.join(eligible[arch])}")
    missing_required = [a for a in args.require if a not in selected]
    for arch in candidates:
        if arch in selected or arch in args.require:
            continue
        print(
            f"::warning::building WITHOUT {arch}: no Ready, schedulable {arch} node admits the build Job "
            f"({_diag(candidates[arch], nodes, arch)}). The image will be {'+'.join(selected)}-only; "
            f"the build returns to multi-arch automatically once a {arch} node is admissible."
        )
    if missing_required:
        for arch in missing_required:
            print(f"::error::required build architecture {arch} has no admissible node "
                  f"({_diag(candidates[arch], nodes, arch)})")
        return 1
    Path(args.output).write_text(" ".join(selected) + "\n")
    print(f"build-arches={' '.join(selected)}")
    return 0


def _diag(pod_spec: dict[str, Any], nodes: list[dict[str, Any]], arch: str) -> str:
    rows = [
        f"{n.get('metadata', {}).get('name')}={node_rejection(pod_spec, n) or 'ok'}"
        for n in nodes if _labels(n).get(ARCH_LABEL) == arch
    ]
    return "; ".join(rows) or f"no nodes labelled {ARCH_LABEL}={arch}"


def _platforms_job(args: argparse.Namespace) -> str:
    labels = {"app": "ci-verify"}
    for item in args.label or []:
        key, _, value = item.partition("=")
        labels[key] = value
    script = (
        "import json, urllib.request\n"
        f"url = 'http://{args.registry}/v2/{args.repo}/manifests/{args.tag}'\n"
        "accept = 'application/vnd.oci.image.index.v1+json,application/vnd.docker.distribution.manifest.list.v2+json'\n"
        "req = urllib.request.Request(url, headers={'Accept': accept})\n"
        "with urllib.request.urlopen(req, timeout=30) as resp:\n"
        "    manifest = json.load(resp)\n"
        "platforms = sorted({\n"
        "    f\"{m.get('platform', {}).get('os')}/{m.get('platform', {}).get('architecture')}\"\n"
        "    for m in manifest.get('manifests', [])\n"
        "})\n"
        f"print('{PLATFORMS_PREFIX}' + json.dumps(platforms))\n"
    )
    job = {
        "apiVersion": "batch/v1",
        "kind": "Job",
        "metadata": {"name": args.job_name, "namespace": args.namespace, "labels": labels},
        "spec": {
            "backoffLimit": 0,
            "activeDeadlineSeconds": args.timeout_seconds,
            "ttlSecondsAfterFinished": 300,
            "template": {"spec": {
                "restartPolicy": "Never",
                "containers": [{
                    "name": "manifest-check",
                    "image": args.image,
                    "command": ["python", "-c", script],
                }],
            }},
        },
    }
    return json.dumps(job)


def parse_platforms_log(text: str) -> list[str]:
    for line in reversed(text.splitlines()):
        line = line.strip()
        if line.startswith(PLATFORMS_PREFIX):
            value = json.loads(line[len(PLATFORMS_PREFIX):])
            if not isinstance(value, list):
                break
            return sorted(str(v) for v in value)
    raise GuardError("manifest-check Job printed no platform list")


def cmd_manifest_platforms(args: argparse.Namespace) -> int:
    job = f"job/{args.job_name}"
    kubectl("delete", job, "-n", args.namespace, "--ignore-not-found=true", "--wait=true", "--timeout=60s")
    kubectl("apply", "-f", "-", stdin=_platforms_job(args))
    deadline = time.monotonic() + args.timeout_seconds
    state = ""
    while time.monotonic() < deadline:
        status = kube_json("get", job, "-n", args.namespace).get("status", {})
        conds = {c.get("type"): c.get("status") for c in status.get("conditions", []) or []}
        if conds.get("Complete") == "True" or status.get("succeeded"):
            state = "complete"
            break
        if conds.get("Failed") == "True" or status.get("failed"):
            state = "failed"
            break
        time.sleep(args.poll_seconds)
    log = kubectl("logs", "-n", args.namespace, job, "--tail=50", check=False)
    if state != "complete":
        print(f"::error::manifest-platforms Job {args.job_name} {state or 'timed out'}")
        sys.stdout.write(log.stdout + log.stderr)
        return 1
    platforms = parse_platforms_log(log.stdout)
    image = f"{args.registry}/{args.repo}:{args.tag}"
    print(f"{image} platforms={platforms}")
    if args.expect is not None:
        expected = sorted(f"linux/{a}" for a in parse_arch_list(args.expect))
        if platforms != expected:
            print(f"::error::{image} platforms {platforms} != built {expected}")
            return 1
    if args.output:
        Path(args.output).write_text(" ".join(p.split("/")[-1] for p in platforms) + "\n")
    return 0


def cmd_check_placement(args: argparse.Namespace) -> int:
    platforms = set(parse_arch_list(args.platforms))
    if not platforms:
        print("::error::check-placement needs a non-empty --platforms list")
        return 1
    nodes = kube_json("get", "nodes").get("items", [])
    failed = False
    for target in args.deployment:
        namespace, _, name = target.partition("/")
        if not namespace or not name:
            raise GuardError(f"--deployment expects NAMESPACE/NAME, got {target!r}")
        proc = kubectl("get", "deployment", name, "-n", namespace, "-o", "json", check=False)
        if proc.returncode:
            if "NotFound" in proc.stderr:
                print(f"placement-check {target}: deployment absent (first install); nothing to cover")
                continue
            raise GuardError(f"cannot read deployment {target}: {proc.stderr.strip()}")
        deployment = json.loads(proc.stdout)
        selector = label_selector(deployment.get("spec", {}).get("selector", {}) or {})
        pods = kube_json("get", "pods", "-n", namespace, "-l", selector).get("items", [])
        by_arch = live_pod_arches(pods, nodes)
        missing = {arch: where for arch, where in by_arch.items() if arch not in platforms}
        summary = ", ".join(f"{a}={len(w)}" for a, w in sorted(by_arch.items())) or "no live pods"
        if missing:
            failed = True
            for arch, where in sorted(missing.items()):
                print(
                    f"::error::refusing rollout of {sorted(platforms)} image: {target} has live pods on "
                    f"{arch} nodes ({', '.join(sorted(where))}); they could not run the new image"
                )
        else:
            print(f"placement-check {target}: OK image={sorted(platforms)} live-pods {summary}")
    return 1 if failed else 0


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.split("\n", 1)[0])
    sub = parser.add_subparsers(dest="command", required=True)

    sel = sub.add_parser("select", help="choose build arches from live node admissibility")
    sel.add_argument("--candidate", action="append", required=True, metavar="ARCH=JOB.json")
    sel.add_argument("--require", action="append", default=[], metavar="ARCH")
    sel.add_argument("--nodes", help="nodes JSON (default: kubectl get nodes)")
    sel.add_argument("--output", required=True, help="file receiving the space-separated arch list")

    man = sub.add_parser("manifest-platforms", help="read (and optionally require) an image index's platforms")
    man.add_argument("--registry", required=True)
    man.add_argument("--repo", required=True)
    man.add_argument("--tag", required=True)
    man.add_argument("--job-name", required=True)
    man.add_argument("--namespace", default="build")
    man.add_argument("--label", action="append", metavar="KEY=VALUE")
    man.add_argument("--image", default="python:3.12-alpine")
    man.add_argument("--expect", help="exact arch list the index must contain (e.g. 'amd64 arm64')")
    man.add_argument("--output", help="file receiving the space-separated arch list")
    man.add_argument("--timeout-seconds", type=int, default=180)
    man.add_argument("--poll-seconds", type=float, default=3.0)

    chk = sub.add_parser("check-placement", help="image platforms must cover live pod node arches")
    chk.add_argument("--platforms", required=True, help="e.g. 'arm64' or 'linux/amd64,linux/arm64'")
    chk.add_argument("--deployment", action="append", required=True, metavar="NAMESPACE/NAME")

    args = parser.parse_args(argv)
    try:
        if args.command == "select":
            return cmd_select(args)
        if args.command == "manifest-platforms":
            return cmd_manifest_platforms(args)
        if args.command == "check-placement":
            return cmd_check_placement(args)
    except GuardError as exc:
        print(f"::error::{exc}")
        return 1
    return 2


if __name__ == "__main__":
    raise SystemExit(main())

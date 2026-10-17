FROM python:3.11-slim

COPY --from=ghcr.io/astral-sh/uv:0.11.26 /uv /uvx /bin/

# Set environment variables
ENV PYTHONDONTWRITEBYTECODE=1
ENV PYTHONUNBUFFERED=1
ENV UV_PYTHON_DOWNLOADS=0
ENV UV_LINK_MODE=copy
ENV PATH="/app/.venv/bin:$PATH"

# Set work directory
WORKDIR /app

# Install system dependencies
RUN apt-get update && apt-get install -y \
    build-essential \
    libpq-dev \
    netcat-openbsd \
    supervisor \
    && rm -rf /var/lib/apt/lists/*

# Create log directories
RUN mkdir -p /var/log/supervisor /var/log/django

# Install Python dependencies from the committed lockfile.
COPY pyproject.toml uv.lock ./
RUN uv sync --locked --no-dev --no-install-project --no-editable

# PLAT-10253: jaraco.context 5.3.0 / wheel 0.45.1 are NOT in uv.lock — they are
# the base image's bundled packaging tools (setuptools deps in system
# site-packages). Upgrade them in-line so the image clears CVE-2026-23949
# (jaraco.context, fixed 6.1.0) and CVE-2026-24049 (wheel, fixed 0.46.2)
# independently of the shared base resnapshot.
RUN uv pip install --python /app/.venv/bin/python3 --no-cache 'jaraco.context>=6.1.0' 'wheel>=0.46.2'

# Copy project
COPY . .

# Copy supervisord config
COPY supervisord.conf /etc/supervisor/conf.d/supervisord.conf

# Expose port
EXPOSE 8001 18102

# Run supervisord
CMD ["supervisord", "-c", "/etc/supervisor/conf.d/supervisord.conf"]

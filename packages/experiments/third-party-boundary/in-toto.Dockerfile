FROM python@sha256:3cd9086bdb30f7c9bc08a3fa621d9842e0d3f6f9291aeb4677e0547817c10b12

RUN python -m pip install --no-cache-dir --disable-pip-version-check \
    in-toto==3.1.0 securesystemslib==1.5.1 cryptography==50.0.2 \
    attrs==26.1.0 iso8601==2.1.0 pathspec==1.1.1 \
    python-dateutil==2.9.0.post0 six==1.17.0 cffi==2.1.1 pycparser==3.0

WORKDIR /probe
ENTRYPOINT ["python", "run_in_toto.py"]

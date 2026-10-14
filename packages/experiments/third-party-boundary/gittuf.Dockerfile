FROM python@sha256:3cd9086bdb30f7c9bc08a3fa621d9842e0d3f6f9291aeb4677e0547817c10b12

RUN curl -fsSL 'https://github.com/gittuf/gittuf/releases/download/v0.16.0/gittuf_0.16.0_linux_amd64' \
      -o /usr/local/bin/gittuf \
    && echo '31ca79426f8c282149df7dd39e30c215684fbd8a18e0557762f54a3ab7f71b91  /usr/local/bin/gittuf' | sha256sum -c - \
    && chmod +x /usr/local/bin/gittuf

WORKDIR /probe
ENTRYPOINT ["python", "run_gittuf.py"]

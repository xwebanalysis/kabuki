FROM python:3.13-slim

WORKDIR /app

RUN apt-get update && apt-get install -y --no-install-recommends \
    git \
    ca-certificates \
    && rm -rf /var/lib/apt/lists/*

ENV PYTHONDONTWRITEBYTECODE 1
ENV PYTHONUNBUFFERED 1

COPY requirements.txt requirements-postgres.txt ./

RUN pip install --no-cache-dir -r requirements-postgres.txt

# xwa-sdk is installed from git because the sibling repo is outside the build context.
# Override with --build-arg XWA_SDK_SPEC="xwa-sdk @ git+https://...@<ref>".
ARG XWA_SDK_SPEC="xwa-sdk @ git+https://github.com/xwebanalysis/xwa-sdk.git#subdirectory=bindings/python"
RUN pip install --no-cache-dir "$XWA_SDK_SPEC"

COPY ./app ./app

EXPOSE 8040

CMD ["uvicorn", "app.main:app", "--host", "0.0.0.0", "--port", "8040", "--reload"]

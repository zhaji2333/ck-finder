# ck-finder 生产镜像（含收集引擎 + 挖洞工具链）
# 多阶段：node:22 构建 → 运行镜像内置 nuclei/sqlmap/dirsearch

FROM node:22-slim AS build
WORKDIR /app
COPY package.json package-lock.json ./
RUN npm ci
COPY tsconfig.json ./
COPY src ./src
COPY frontend ./frontend
RUN npm run build && npm run web:build

FROM node:22-slim
WORKDIR /app

# 运行时系统依赖 + 安全工具链
RUN apt-get update && apt-get install -y --no-install-recommends \
      ca-certificates curl wget python3 python3-pip git \
    && rm -rf /var/lib/apt/lists/*

# nuclei（GitHub release 二进制）
ARG NUCLEI_VERSION=3.3.7
RUN wget -qO /tmp/nuclei.zip "https://github.com/projectdiscovery/nuclei/releases/download/v${NUCLEI_VERSION}/nuclei_${NUCLEI_VERSION}_linux_amd64.zip" \
    && unzip -o /tmp/nuclei.zip -d /usr/local/bin/ nuclei \
    && chmod +x /usr/local/bin/nuclei && rm /tmp/nuclei.zip

# sqlmap（pip）
RUN pip3 install --no-cache-dir sqlmap

# dirsearch（git clone，用 python 调用）
RUN git clone --depth 1 https://github.com/maurosoria/dirsearch.git /opt/dirsearch

# npm 依赖 + 构建产物
COPY package.json package-lock.json ./
RUN npm ci --omit=dev
COPY --from=build /app/dist ./dist
COPY --from=build /app/frontend/dist ./frontend/dist
COPY web ./web
COPY skills ./skills
COPY migrations ./migrations
COPY scripts/migrate.ts ./scripts/migrate.ts

ENV NODE_ENV=production
EXPOSE 8787

# 启动：迁移 + Web 控制台（server）；挖洞用 queue worker
CMD ["sh", "-c", "node dist/recon/migrate.js 2>/dev/null; node dist/index.js server"]

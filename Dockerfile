# Official Playwright image: Chromium and its system libraries match playwright@1.63.0.
FROM mcr.microsoft.com/playwright:v1.63.0-noble
ENV NODE_ENV=production \
    PLAYWRIGHT_BROWSERS_PATH=/ms-playwright \
    DATA_DIR=/data \
    HOST=0.0.0.0
WORKDIR /app
COPY package.json package-lock.json ./
RUN npm ci --omit=dev --ignore-scripts && npm cache clean --force
COPY src ./src
COPY scripts/docker-start.mjs ./scripts/docker-start.mjs
RUN mkdir -p /data && chown -R pwuser:pwuser /data
USER pwuser
EXPOSE 9310
CMD ["node", "scripts/docker-start.mjs"]

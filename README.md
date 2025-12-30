README.md
# PMESP API (FastAPI + Postgres via Docker Compose)

## Subir localmente
```bash
docker compose up -d --build
docker compose ps
docker compose logs -n 50 api

Endpoints


GET /health


POST /public/register (cria usuário PENDENTE: validade 0, is_active=false)


POST /auth/login


GET /me


GET /admin/users/pending


POST /admin/users/{username}/approve (ADMIN aprova e define dias + limite)


Teste rápido
curl -I http://127.0.0.1:8000/docs

curl -s http://127.0.0.1:8000/public/register \
  -H "Content-Type: application/json" \
  -d '{"username":"joao","password":"Senha@123","email":"joao@teste.com","matricula":"123"}'
echo

curl -s http://127.0.0.1:8000/auth/login \
  -H "Content-Type: application/json" \
  -d '{"username":"joao","password":"Senha@123"}'
echo

TOKEN=$(curl -s http://127.0.0.1:8000/auth/login \
  -H "Content-Type: application/json" \
  -d '{"username":"admin","password":"Admin@123456"}' | jq -r .access_token)

curl -s http://127.0.0.1:8000/admin/users/joao/approve \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"days":30,"session_limit":1}'
echo

Deploy na VPS (clone + up)
apt update -y
apt install -y git docker.io docker-compose-plugin jq
systemctl enable --now docker

git clone https://github.com/SEUUSER/SEUREPO.git /opt/pmesp-api
cd /opt/pmesp-api
docker compose up -d --build

Update
cd /opt/pmesp-api
git pull
docker compose up -d --build


---

# 2) Subir isso pro GitHub (rápido)

No seu PC:

```bash
mkdir pmesp-api && cd pmesp-api
# (crie os arquivos acima aqui dentro)

git init
git add .
git commit -m "Initial PMESP API stack"
git branch -M main

# depois crie o repo no GitHub e cole a URL:
git remote add origin https://github.com/SEUUSER/pmesp-api.git
git push -u origin main


3) Na VPS: só “clone e roda”


apt update -y
apt install -y git docker.io docker-compose jq openssl

systemctl enable --now docker

docker --version
docker compose version || docker-compose version

git clone https://github.com/ColtSeals/pmesp-api.git /opt/pmesp-api
cd /opt/pmesp-api

# sobe (tenta "docker compose", se não tiver cai pro "docker-compose")
docker compose up -d --build || docker-compose up -d --build

docker ps
docker compose logs -n 50 api || docker-compose logs -n 50 api









Se você quiser, eu também já deixo esse repo “mais redondo” com:


endpoint de aprovação por planos (7/30/90),


rota admin para desativar,


expiração automática (e retornar motivo no login),


e limite de sessão real (bloquear tokens quando exceder).


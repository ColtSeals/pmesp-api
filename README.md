

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









Teste rápido (passo a passo)
0) Ver docs
curl -I http://127.0.0.1:8000/docs | head

1) Criar usuário (fica pendente)
curl -s http://127.0.0.1:8000/public/register \
  -H "Content-Type: application/json" \
  -d '{"username":"joao","password":"Senha@123","email":"joao@teste.com","matricula":"123"}'
echo

2) Tentar login antes de aprovar (deve falhar)
curl -s http://127.0.0.1:8000/auth/login \
  -H "Content-Type: application/json" \
  -d '{"username":"joao","password":"Senha@123","hwid":"PC-JOAO-12345678"}'
echo

3) Login do ADMIN (pegando user/pass do .env)
ADMIN_USER=$(grep '^ADMIN_USER=' .env | cut -d= -f2- | tr -d '\r' | tr '[:upper:]' '[:lower:]')
ADMIN_PASSWORD=$(grep '^ADMIN_PASSWORD=' .env | cut -d= -f2- | tr -d '\r')

ADMIN_TOKEN=$(curl -s http://127.0.0.1:8000/auth/login \
  -H "Content-Type: application/json" \
  -d "{\"username\":\"$ADMIN_USER\",\"password\":\"$ADMIN_PASSWORD\",\"hwid\":\"PC-ADMIN-00000000\"}" | jq -r .access_token)

echo "ADMIN_TOKEN=$ADMIN_TOKEN"

4) Aprovar o usuário (30 dias, limite 1 sessão)
curl -s http://127.0.0.1:8000/admin/users/joao/approve \
  -H "Authorization: Bearer $ADMIN_TOKEN" \
  -H "Content-Type: application/json" \
  -H "X-HWID: PC-ADMIN-00000000" \
  -d '{"days":30,"session_limit":1}'
echo

5) Login do usuário aprovado (com HWID)
JOAO_TOKEN=$(curl -s http://127.0.0.1:8000/auth/login \
  -H "Content-Type: application/json" \
  -d '{"username":"joao","password":"Senha@123","hwid":"PC-JOAO-12345678"}' | jq -r .access_token)

echo "JOAO_TOKEN=$JOAO_TOKEN"

6) Chamar /me (token + X-HWID obrigatório)
curl -s http://127.0.0.1:8000/me \
  -H "Authorization: Bearer $JOAO_TOKEN" \
  -H "X-HWID: PC-JOAO-12345678"
echo

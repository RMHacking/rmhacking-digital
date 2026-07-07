# 🚀 RMHacking — Guia de Deploy

## ▶ Rodar Localmente (mais rápido)

```bash
# 1. Instale o Node.js (https://nodejs.org) se não tiver
# 2. Abra o terminal na pasta do projeto
cd investigacao-digital

# 3. Instale as dependências
npm install

# 4. Configure sua senha (opcional — padrão: rmhacking2024)
# Crie um arquivo .env na raiz:
# ACCESS_PASSWORD=suasenhaaqui

# 5. Inicie o servidor
npm start

# 6. Acesse no navegador:
# http://localhost:3000
```

---

## ☁️ Deploy no Railway (recomendado — GRATUITO)

### Passo a Passo:

1. **Crie uma conta em** [railway.app](https://railway.app) (login com GitHub)

2. **Faça upload do projeto:**
   - Opção A: Conecte ao GitHub (push do projeto para um repositório privado)
   - Opção B: Use o Railway CLI:
     ```bash
     npm install -g @railway/cli
     railway login
     railway init
     railway up
     ```

3. **Configure as variáveis de ambiente no Railway:**
   - Vá em: seu projeto → Settings → Variables
   - Adicione:
     ```
     ACCESS_PASSWORD = sua_senha_escolhida
     SESSION_SECRET  = string_aleatoria_longa_aqui
     PORT            = 3000
     DB_PATH         = /data/rmhacking.db
     ```

4. **Configure volume persistente para o banco de dados:**
   - Vá em: Settings → Volumes
   - Mount path: `/data`
   - Isso garante que os dados não se percam ao reiniciar

5. **Deploy automático** — o Railway detecta o `package.json` e inicia automaticamente

6. **Acesse a URL** gerada (ex: `https://rmhacking-xxxxx.up.railway.app`)

---

## ☁️ Deploy no Render (alternativa gratuita)

1. Acesse [render.com](https://render.com) e crie uma conta
2. Clique em "New Web Service"
3. Conecte seu repositório GitHub
4. Configurações:
   - **Build Command:** `npm install`
   - **Start Command:** `node server.js`
   - **Environment:** Node
5. Adicione as variáveis de ambiente (mesmas do Railway)
6. **Disk:** Adicione um disco persistente em `/data`

---

## 🐍 Ferramentas Python (CLI)

```bash
# Instale o Python 3.8+ se não tiver

# Instale dependência opcional (para EXIF)
pip install Pillow

# Execute o orquestrador CLI
python app.py

# Ou use os módulos diretamente:
python core/forensics.py /caminho/para/arquivo.jpg
python core/osint.py
python core/analyzer.py
```

---

## 🔐 Segurança

- **SEMPRE** altere `ACCESS_PASSWORD` antes do deploy
- Use uma senha forte (12+ caracteres, letras, números e símbolos)
- Nunca compartilhe o arquivo `.env`
- O banco `.db` contém TODOS os dados — faça backup regularmente

---

## 📞 Suporte

Sistema desenvolvido para uso exclusivo de Rafael Moreno — RMHacking.

# Deploy — RMHacking Digital no Vercel + Firebase Firestore

## Pré-requisitos
- Conta no Vercel (vercel.com) — você já tem ✅
- Conta no Firebase (firebase.google.com) — você já tem ✅
- Git instalado no computador

---

## PASSO 1 — Configurar Firebase Firestore

1. Acesse **console.firebase.google.com**
2. Selecione seu projeto (ou crie um novo)
3. No menu lateral: **Firestore Database → Criar banco de dados**
4. Escolha **Modo de produção** → selecione uma região (ex: `us-east1`) → **Concluir**

### Regras de segurança do Firestore
Em **Firestore → Regras**, cole:
```
rules_version = '2';
service cloud.firestore {
  match /databases/{database}/documents {
    match /{document=**} {
      allow read, write: if false;
    }
  }
}
```
*(o acesso é feito somente pelo servidor, nunca direto do browser)*

### Gerar chave de serviço (Service Account)
1. **Configurações do projeto (⚙️) → Contas de serviço**
2. Clique em **Gerar nova chave privada**
3. Um arquivo `.json` será baixado — **guarde com segurança, não compartilhe**

---

## PASSO 2 — Preparar o código no GitHub

Abra o terminal no Windows (CMD ou PowerShell) dentro da pasta do projeto:

```bash
cd C:\Users\User\Documents\CashPay\rmhacking-investigacao-digital\investigacao-digital

# Inicializar repositório Git
git init
git add .
git commit -m "RMHacking Digital v2 - Firebase + Vercel"

# Criar repositório no GitHub (acesse github.com → New repository)
# Nome sugerido: rmhacking-digital
# Visibilidade: Privado (recomendado)

# Conectar e enviar
git remote add origin https://github.com/SEU_USUARIO/rmhacking-digital.git
git branch -M main
git push -u origin main
```

---

## PASSO 3 — Deploy no Vercel

1. Acesse **vercel.com → Add New → Project**
2. Clique em **Import** no repositório `rmhacking-digital`
3. Em **Framework Preset**: selecione **Other**
4. Clique em **Deploy** (vai falhar na primeira vez, normal — precisa configurar as variáveis)

---

## PASSO 4 — Configurar variáveis de ambiente no Vercel

No painel do projeto Vercel: **Settings → Environment Variables**

Adicione estas variáveis:

| Nome | Valor |
|------|-------|
| `FIREBASE_SERVICE_ACCOUNT` | *Todo o conteúdo do arquivo .json baixado no Passo 1* (cole o JSON completo) |
| `ACCESS_PASSWORD` | `rmhacking2024` (ou a senha que preferir) |
| `SESSION_SECRET` | Qualquer string aleatória longa, ex: `rmh2024xk9jw3nq7` |
| `NODE_ENV` | `production` |

Depois vá em **Deployments → clique nos 3 pontinhos → Redeploy**

---

## PASSO 5 — Acessar o sistema

Após o deploy bem-sucedido, o Vercel mostrará a URL do seu sistema, algo como:
```
https://rmhacking-digital.vercel.app
```

Acesse de qualquer dispositivo com essa URL! ✅

---

## PASSO 6 — Migrar dados existentes

Para não perder as investigações do sistema local:

1. Abra o sistema **local** (localhost:3000)
2. Para cada investigação: **Relatório → Exportar Backup** (gera um arquivo `.rmh.json`)
3. Abra o sistema **Vercel** (nova URL)
4. Faça login e vá em **Configurações → Restaurar Backup**
5. Importe cada arquivo `.rmh.json`

---

## Uso local (desenvolvimento)

Para continuar usando localmente com Firestore:
1. Coloque o arquivo `serviceAccountKey.json` na pasta do projeto
2. Execute `npm install && node server.js`

---

## Observações

- **Dados**: ficam no Firebase Firestore — seguros, com backup automático do Google
- **Uploads de arquivo**: temporários por enquanto (tarefa pendente — Firebase Storage)
- **URL**: atualiza automaticamente a cada `git push`
- **Custo**: gratuito no plano Hobby do Vercel + gratuito no Spark do Firebase

# Orchestrator + Browser Runner

## Requisitos
- Node.js 20+
- No Render, 2 serviços: Orchestrator e Runner

## Instalação local
1. `npm install`
2. `npm start` (orchestrator em :8080)
3. `npm run runner` (runner em :8090)

## Configuração
- Copie `.env.example` para `.env` e preencha.
- Grave credenciais: faça POST em `/api/secrets/set` com `provider`, `key`, `value`.

## Fluxo rápido
1. Crie uma demanda: `POST /api/orch/demand/new`.
2. Dispare fan‑out:
```json
{
  "demandId": "ID",
  "steps": [
    {"kind": "browser-action", "provider": "chatgpt", "payload": {"prompt": "Seu prompt"}},
    {"kind": "browser-action", "provider": "manus",   "payload": {"prompt": "Seu prompt"}}
  ]
}

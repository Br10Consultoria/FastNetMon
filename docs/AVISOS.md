# Avisos por e-mail e webhook

Complementam o Telegram. Todo aviso que vai ao Telegram — ataques do detector, alarmes por filtro, saúde e
reputação — também vai para o e-mail e/ou webhook configurados na página **E-mail/Webhook** do painel
(`/etc/orbymon/notify.env`, lido como dados).

- **E-mail (SMTP)**: STARTTLS (587), SSL/TLS (465) ou sem criptografia (25); vários destinatários; assunto = primeira
  linha do aviso; corpo em texto e HTML.
- **Webhook**: POST JSON. Formatos: genérico (`{"origem","site","texto","html"}`), Slack/Mattermost/Rocket.Chat
  (`text`), Discord (`content`) e Microsoft Teams (`text`).
- O Telegram continua como canal principal: se ele falhar, o aviso é tentado de novo na próxima rodada. Falha de
  e-mail/webhook fica só no log do serviço (sem a URL, que pode conter token).
- Senha SMTP e URL do webhook são só de escrita no painel (vazio = manter). **Enviar teste** valida sem salvar.

Requer o `setup-admin.sh` atualizado (cria `notify.env` e a variável do painel):

```bash
cd /opt/orbymon && sudo git pull && sudo bash scripts/setup-admin.sh
```

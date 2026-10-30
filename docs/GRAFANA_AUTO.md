# OrbyMon: Grafana automatico, MariaDB e dashboards

## Um comando no Ubuntu 24.04

Para o servidor piloto flow, onde o banco orbymon e a coleta NetFlow ja funcionam:

    cd /opt/orbymon
    git pull --ff-only origin main
    sudo bash scripts/setup-grafana.sh --public-host 187.87.201.198

Substitua 187.87.201.198 se o IP ou dominio publico do servidor for diferente.

O script:
- instala Grafana se necessario, desde que o repositorio APT Grafana esteja configurado;
- cria usuario MariaDB orbymon_grafana apenas com SELECT;
- gera senha forte para datasource, protegida em /etc/orbymon/grafana.env;
- configura datasource MySQL/MariaDB UID orbymon-mysql e timezone +00:00;
- instala TODOS os arquivos JSON da pasta grafana/dashboards/;
- provisiona a pasta OrbyMon no Grafana, sem importacao manual;
- habilita Grafana no boot e publica HTTPS na porta 3000;
- usa certificado autofirmado temporario com IP/dominio no SAN;
- preserva arquivos e credenciais em futuras execucoes;
- nao reinicia nfcapd nem muda Huawei/BGP/PPPoE/firewall/rotas.

## Acesso

Abra https://187.87.201.198:3000/

Se o Grafana nunca foi iniciado, usuario admin e senha aleatoria serao criados,
registrados apenas em /root/orbymon-grafana-acesso.txt (modo 0600):

    sudo cat /root/orbymon-grafana-acesso.txt

Se o Grafana ja tinha banco inicializado, o script preserva a conta e a senha admin existentes.

O certificado HTTPS e autofirmado e o navegador exibira aviso. Compare a
impressao digital exibida no navegador com:

    openssl x509 -in /etc/orbymon/grafana-tls/grafana.crt -noout -fingerprint -sha256

Para uso definitivo, utilize dominio e certificado TLS confiavel; restrinja
acesso somente a IPs do provedor e de sua residencia. O instalador NAO altera
firewall, NAT ou regras de acesso. TCP 3000 precisa estar permitido na borda.
NAO exponha TCP 3306.

## Validar

    sudo systemctl is-active grafana-server
    sudo ss -lntp | grep 3000
    curl -ks https://127.0.0.1:3000/api/health
    sudo journalctl -u grafana-server -n 60 --no-pager
    sudo mariadb orbymon -e "SELECT COUNT(*) FROM orby_ingested_files"

No Grafana, abra a pasta OrbyMon. Os paineis importados sao:
- OrbyMon | Huawei - Trafego em tempo real: Mbps, PPS, volume, ASN, porta e fluxos.
- OrbyMon | Trafego, ASN e Defesa DDoS: dashboards existentes de trafego e alertas.

Alguns painéis de alertas, paises e mapa permanecem vazios ate que o
detector e GeoLite2 sejam integrados. Os valores Mbps e PPS sao ESTIMATIVAS
de fluxos amostrados 1:2048 ja expandidos pelo nfdump, agrupados no minuto
final do fluxo. O banco atualmente nao registra ranking de IP individual.

O Grafana valida a importacao em runtime no servidor; os testes do
repositorio validam sintaxe, estrutura e referencias do dashboard.

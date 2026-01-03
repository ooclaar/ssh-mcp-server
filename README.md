# SSH MCP Server 🔐

Servidor MCP (Model Context Protocol) que permite ao Claude conectar e executar comandos em servidores remotos via SSH.

## 🚀 Instalação Rápida

### Opção 1: Via Git URL (recomendado)

Adicione ao seu `claude_desktop_config.json`:

```json
{
  "mcpServers": {
    "ssh": {
      "command": "uvx",
      "args": [
        "--from",
        "git+https://github.com/SEU-USUARIO/ssh-mcp-server",
        "ssh-mcp-server"
      ]
    }
  }
}
```

### Opção 2: Instalação local

```bash
# Clone o repositório
git clone https://github.com/SEU-USUARIO/ssh-mcp-server
cd ssh-mcp-server

# Instale
pip install -e .
```

Depois adicione ao `claude_desktop_config.json`:

```json
{
  "mcpServers": {
    "ssh": {
      "command": "ssh-mcp-server"
    }
  }
}
```

### Opção 3: Via npx (se publicado no npm)

```json
{
  "mcpServers": {
    "ssh": {
      "command": "npx",
      "args": ["-y", "ssh-mcp-server"]
    }
  }
}
```

## 📍 Localização do arquivo de configuração

| Sistema | Caminho |
|---------|---------|
| macOS | `~/Library/Application Support/Claude/claude_desktop_config.json` |
| Windows | `%APPDATA%\Claude\claude_desktop_config.json` |
| Linux | `~/.config/Claude/claude_desktop_config.json` |

## 🛠️ Ferramentas Disponíveis

Após configurar, o Claude terá acesso às seguintes ferramentas:

### `ssh_connect`
Conecta a um servidor SSH.

**Parâmetros:**
- `hostname` (obrigatório): IP ou hostname do servidor
- `username` (obrigatório): Usuário SSH
- `password`: Senha (opcional se usar chave)
- `private_key`: Conteúdo da chave privada SSH
- `port`: Porta SSH (padrão: 22)

### `ssh_execute`
Executa comandos no servidor conectado.

**Parâmetros:**
- `command` (obrigatório): Comando bash a executar
- `timeout`: Timeout em segundos (padrão: 60)

### `ssh_upload`
Cria/sobrescreve arquivo no servidor.

**Parâmetros:**
- `remote_path` (obrigatório): Caminho do arquivo
- `content` (obrigatório): Conteúdo do arquivo

### `ssh_download`
Lê conteúdo de arquivo remoto.

**Parâmetros:**
- `remote_path` (obrigatório): Caminho do arquivo

### `ssh_list`
Lista arquivos em diretório.

**Parâmetros:**
- `path`: Caminho a listar (padrão: diretório atual)

### `ssh_info`
Mostra status da conexão atual.

### `ssh_disconnect`
Encerra a conexão SSH.

## 💬 Exemplos de Uso com Claude

Após configurar, você pode simplesmente pedir ao Claude:

```
"Conecte no servidor 192.168.1.100 com usuário admin e senha secret123"

"Execute df -h para ver o espaço em disco"

"Liste os arquivos em /var/log"

"Crie um arquivo /tmp/teste.txt com o conteúdo 'Hello World'"

"Mostre o conteúdo do arquivo /etc/hostname"

"Verifique os processos rodando com ps aux"

"Desconecte do servidor"
```

## 🔑 Usando Chave SSH

Para conectar com chave privada, você pode:

1. **Copiar o conteúdo da chave** e passar para o Claude:
```
Conecte no servidor srv.exemplo.com com usuário deploy usando esta chave:
-----BEGIN OPENSSH PRIVATE KEY-----
...conteúdo da chave...
-----END OPENSSH PRIVATE KEY-----
```

2. **Ou pedir ao Claude para ler** (se tiver acesso ao filesystem):
```
Leia minha chave SSH em ~/.ssh/id_rsa e use para conectar em srv.exemplo.com
```

## ⚠️ Segurança

- **Nunca compartilhe** senhas ou chaves em conversas públicas
- As credenciais são usadas apenas durante a sessão
- Nenhuma credencial é armazenada permanentemente
- Use chaves SSH sempre que possível (mais seguro que senhas)
- Considere usar variáveis de ambiente para credenciais sensíveis

## 🔧 Desenvolvimento

```bash
# Clone
git clone https://github.com/SEU-USUARIO/ssh-mcp-server
cd ssh-mcp-server

# Crie ambiente virtual
python -m venv venv
source venv/bin/activate  # Linux/Mac
# ou: venv\Scripts\activate  # Windows

# Instale em modo desenvolvimento
pip install -e ".[dev]"

# Teste localmente
python -m ssh_mcp_server
```

## 📋 Requisitos

- Python 3.10+
- paramiko >= 3.0.0
- mcp >= 1.0.0

## 🐛 Troubleshooting

### "Ferramenta ssh não encontrada"
- Verifique se o `claude_desktop_config.json` está no local correto
- Reinicie o Claude Desktop após editar a configuração

### "Falha na autenticação"
- Verifique usuário/senha
- Se usar chave, verifique se o formato está correto (deve incluir headers)

### "Timeout ao conectar"
- Verifique conectividade de rede
- Verifique se a porta SSH está correta e aberta
- Tente aumentar o timeout

### "Erro: mcp module not found"
- Execute: `pip install mcp paramiko`

## 📄 Licença

MIT License - use como quiser!

## 🤝 Contribuindo

PRs são bem-vindos! Por favor:

1. Fork o repositório
2. Crie uma branch (`git checkout -b feature/minha-feature`)
3. Commit suas mudanças (`git commit -am 'Add feature'`)
4. Push para a branch (`git push origin feature/minha-feature`)
5. Abra um Pull Request

#!/usr/bin/env python3
"""
SSH MCP Server - Servidor MCP para conexoes SSH remotas
Permite ao Claude conectar e executar comandos em servidores via SSH.
"""

import asyncio
import os
import sys
from typing import Optional
from contextlib import asynccontextmanager

import paramiko
from mcp.server import Server
from mcp.server.stdio import stdio_server
from mcp.types import (
    Tool,
    TextContent,
)

# Configura encoding UTF-8 para stdout/stderr no Windows
if sys.platform == "win32":
    import io
    sys.stdout = io.TextIOWrapper(sys.stdout.buffer, encoding='utf-8', errors='replace')
    sys.stderr = io.TextIOWrapper(sys.stderr.buffer, encoding='utf-8', errors='replace')

import time

# Armazena sessoes SSH ativas
ssh_sessions: dict[str, "SSHSession"] = {}

class SSHSession:
    """Gerencia uma sessao SSH persistente"""

    def __init__(self, session_id: str):
        self.session_id = session_id
        self.client: Optional[paramiko.SSHClient] = None
        self.hostname: str = ""
        self.username: str = ""
        self.port: int = 22
        self.connected: bool = False
        self.current_dir: str = "~"
        
        # Armazena credenciais para reconexao automatica
        self._password: Optional[str] = None
        self._private_key: Optional[str] = None
        
        # Timeout de inatividade (30 minutos)
        self._last_activity: float = 0.0
        self._timeout_seconds: float = 1800.0  # 30 minutos

    def _update_activity(self):
        """Atualiza carimbo de tempo da ultima atividade."""
        self._last_activity = time.time()

    def _check_timeout(self) -> bool:
        """Verifica se houve timeout por inatividade. Retorna True se timed out."""
        if not self.connected:
            return False
            
        if time.time() - self._last_activity > self._timeout_seconds:
            self.disconnect()
            return True
        return False

    def _reconnect(self) -> bool:
        """Tenta restabelecer a conexao perdida."""
        print(f"Tentando reconectar a {self.username}@{self.hostname}...", file=sys.stderr)
        try:
            if self.client:
                self.client.close()
            
            # Reutiliza logica de conexao mas mantendo estado interno
            success, _ = self.connect(
                self.hostname, 
                self.username, 
                self._password, 
                self._private_key, 
                self.port
            )
            return success
        except Exception as e:
            print(f"Falha na reconexao: {e}", file=sys.stderr)
            return False

    def connect(
        self,
        hostname: str,
        username: str,
        password: Optional[str] = None,
        private_key: Optional[str] = None,
        port: int = 22,
        timeout: int = 30,
    ) -> tuple[bool, str]:
        """Estabelece conexao SSH com o servidor remoto."""
        try:
            self.client = paramiko.SSHClient()
            self.client.set_missing_host_key_policy(paramiko.AutoAddPolicy())

            # Armazena credenciais
            self._password = password
            self._private_key = private_key

            connect_kwargs = {
                "hostname": hostname,
                "username": username,
                "port": port,
                "timeout": timeout,
                "allow_agent": False,
                "look_for_keys": False,
            }

            if private_key:
                # Carrega chave privada da string
                from io import StringIO

                # Tenta diferentes tipos de chave
                key = None
                key_types = [
                    paramiko.RSAKey,
                    paramiko.Ed25519Key,
                    paramiko.ECDSAKey,
                    paramiko.DSSKey,
                ]

                for key_class in key_types:
                    try:
                        key = key_class.from_private_key(StringIO(private_key))
                        break
                    except Exception:
                        continue

                if key is None:
                    return False, "Nao foi possivel carregar a chave privada. Verifique o formato."

                connect_kwargs["pkey"] = key

            if password:
                connect_kwargs["password"] = password

            if not password and not private_key:
                return False, "E necessario fornecer senha ou chave privada"

            self.client.connect(**connect_kwargs)
            
            # Habilita keep-alive (a cada 30s envia pacote dummy)
            self.client.get_transport().set_keepalive(30)

            self.hostname = hostname
            self.username = username
            self.port = port
            self.connected = True
            
            # Inicializa timer de inatividade
            self._update_activity()

            # Obtem diretorio atual se nao estiver reconectando (usa ~ se falhar)
            if self.current_dir == "~":
                try:
                    _, stdout, _ = self.client.exec_command("pwd")
                    self.current_dir = stdout.read().decode().strip()
                except:
                    pass

            return True, f"Conectado a {username}@{hostname}:{port}"

        except paramiko.AuthenticationException:
            return False, "Falha na autenticacao: credenciais invalidas"
        except paramiko.SSHException as e:
            return False, f"Erro SSH: {str(e)}"
        except TimeoutError:
            return False, f"Timeout ao conectar em {hostname}:{port}"
        except Exception as e:
            return False, f"Erro ao conectar: {str(e)}"

    def execute(self, command: str, timeout: int = 60) -> dict:
        """Executa um comando no servidor remoto."""
        if self._check_timeout():
            return {
                "success": False,
                "stdout": "",
                "stderr": "Conexao encerrada por inatividade (> 30 min). Reconecte.",
                "exit_code": -1,
            }

        if not self.connected or not self.client:
            return {
                "success": False,
                "stdout": "",
                "stderr": "Nao conectado. Use ssh_connect primeiro.",
                "exit_code": -1,
            }

        retries = 1
        while retries >= 0:
            try:
                # Prepara o comando
                # Se comeca com cd, precisamos capturar o novo diretorio na mesma execucao
                # para evitar re-executar comandos com efeitos colaterais (ex: cd x && nmap ...)
                is_cd_command = command.strip().startswith("cd ")
                pwd_marker = "___MCP_PWD_MARKER___"
                
                if is_cd_command:
                    # Executa: cd atual; comando; guarda exit code; echo marker + pwd; exit com exit code
                    full_command = f"cd {self.current_dir} 2>/dev/null; {command}; RC=$?; echo; echo '{pwd_marker}'$(pwd); exit $RC"
                else:
                    # Executa normal no diretorio atual
                    full_command = f"cd {self.current_dir} 2>/dev/null; {command}"

                _, stdout, stderr = self.client.exec_command(full_command, timeout=timeout)

                stdout_text = stdout.read().decode("utf-8", errors="replace")
                stderr_text = stderr.read().decode("utf-8", errors="replace")
                exit_code = stdout.channel.recv_exit_status()

                # Se foi um comando cd, processa a saida para extrair o novo diretorio
                if is_cd_command:
                    # Procura o marcador no final da saida
                    if pwd_marker in stdout_text:
                        parts = stdout_text.rsplit(pwd_marker, 1)
                        real_stdout = parts[0]
                        new_pwd = parts[1].strip()
                        
                        # Remove a quebra de linha extra que colocamos antes do marcador
                        if real_stdout.endswith("\n"):
                            real_stdout = real_stdout[:-1]
                            
                        stdout_text = real_stdout
                        
                        if new_pwd:
                            self.current_dir = new_pwd
                
                self._update_activity()
                return {
                    "success": exit_code == 0,
                    "stdout": stdout_text,
                    "stderr": stderr_text,
                    "exit_code": exit_code,
                    "cwd": self.current_dir,
                }

            except (paramiko.SSHException, BrokenPipeError, ConnectionResetError) as e:
                if retries > 0:
                    print(f"Erro de conexao ({e}), tentando reconectar...", file=sys.stderr)
                    if self._reconnect():
                        retries -= 1
                        continue
                
                return {
                    "success": False,
                    "stdout": "",
                    "stderr": f"Erro de conexao: {str(e)}",
                    "exit_code": -1,
                }
            except Exception as e:
                return {
                    "success": False,
                    "stdout": "",
                    "stderr": f"Erro: {str(e)}",
                    "exit_code": -1,
                }
            
            # Se chegou aqui sem retornar e sem exception (loop break), break just in case
            break

    def upload_file(self, content: str, remote_path: str) -> tuple[bool, str]:
        """Faz upload de conteudo para um arquivo remoto."""
        if self._check_timeout():
            return False, "Conexao encerrada por inatividade (> 30 min)"

        if not self.connected or not self.client:
            return False, "Nao conectado"

        retries = 1
        while retries >= 0:
            try:
                sftp = self.client.open_sftp()

                # Expande ~ no caminho remoto
                target_path = remote_path
                if target_path.startswith("~"):
                    target_path = target_path.replace("~", self.current_dir.split("/")[0] or "/root", 1)

                with sftp.file(target_path, "w") as f:
                    f.write(content)
                sftp.close()
                self._update_activity()
                return True, f"Arquivo criado: {remote_path}"
            
            except (paramiko.SSHException, OSError) as e: # OSError often wraps socket errors in paramiko
                if retries > 0 and (not self.client.get_transport() or not self.client.get_transport().is_active()):
                     if self._reconnect():
                        retries -= 1
                        continue
                return False, f"Erro no upload: {str(e)}"
            except Exception as e:
                return False, f"Erro no upload: {str(e)}"
            
            break

    def download_file(self, remote_path: str) -> tuple[bool, str]:
        """Faz download do conteudo de um arquivo remoto."""
        if self._check_timeout():
            return False, "Conexao encerrada por inatividade (> 30 min)"
            
        if not self.connected or not self.client:
            return False, "Nao conectado"

        retries = 1
        while retries >= 0:
            try:
                sftp = self.client.open_sftp()
                with sftp.file(remote_path, "r") as f:
                    content = f.read().decode("utf-8", errors="replace")
                sftp.close()
                self._update_activity()
                return True, content
            except (paramiko.SSHException, OSError) as e:
                if retries > 0 and (not self.client.get_transport() or not self.client.get_transport().is_active()):
                     if self._reconnect():
                        retries -= 1
                        continue
                return False, f"Erro no download: {str(e)}"
            except Exception as e:
                return False, f"Erro no download: {str(e)}"
            break

    def list_dir(self, path: str = ".") -> tuple[bool, str]:
        """Lista arquivos em um diretorio remoto."""
        if self._check_timeout():
            return False, "Conexao encerrada por inatividade (> 30 min)"

        if not self.connected or not self.client:
            return False, "Nao conectado"

        retries = 1
        while retries >= 0:
            try:
                sftp = self.client.open_sftp()
                if path == ".":
                    path = self.current_dir

                files = sftp.listdir_attr(path)
                sftp.close()

                result = []
                for f in files:
                    is_dir = f.st_mode and (f.st_mode & 0o40000)
                    file_type = "[DIR]" if is_dir else "[FILE]"
                    size = f"{f.st_size:,}" if f.st_size else "-"
                    result.append(f"{file_type} {f.filename:<40} {size:>12}")
                
                self._update_activity()
                return True, "\n".join(result) if result else "(diretorio vazio)"
            except (paramiko.SSHException, OSError) as e:
                 if retries > 0 and (not self.client.get_transport() or not self.client.get_transport().is_active()):
                     if self._reconnect():
                        retries -= 1
                        continue
                 return False, f"Erro ao listar: {str(e)}"
            except Exception as e:
                return False, f"Erro ao listar: {str(e)}"
            break

    def disconnect(self) -> str:
        """Encerra a conexao SSH."""
        if self.client:
            self.client.close()
        self.connected = False
        return "Desconectado"

    def get_info(self) -> str:
        """Retorna informacoes sobre a conexao atual."""
        status = "Conectado" if self.connected else "Desconectado"
        if self.connected and self._check_timeout(): # Check timeout just to update status if needed
             status = "Desconectado (Timeout)"
        
        if not self.connected:
            return f"Status: {status}\nUse ssh_connect para conectar a um servidor."

        return f"""Status: {status}
Servidor: {self.username}@{self.hostname}:{self.port}
Diretorio atual: {self.current_dir}
Ultima atividade: {time.ctime(self._last_activity)}"""


def get_session(session_id: str = "default") -> SSHSession:
    """Obtem ou cria uma sessao SSH."""
    if session_id not in ssh_sessions:
        ssh_sessions[session_id] = SSHSession(session_id)
    return ssh_sessions[session_id]


# Cria o servidor MCP
app = Server("ssh-mcp-server")


@app.list_tools()
async def list_tools() -> list[Tool]:
    """Lista as ferramentas SSH disponiveis."""
    return [
        Tool(
            name="ssh_connect",
            description="Conecta a um servidor SSH remoto. Forneca hostname, username e password OU private_key.",
            inputSchema={
                "type": "object",
                "properties": {
                    "hostname": {
                        "type": "string",
                        "description": "Hostname ou IP do servidor",
                    },
                    "username": {
                        "type": "string",
                        "description": "Nome de usuario SSH",
                    },
                    "password": {
                        "type": "string",
                        "description": "Senha SSH (opcional se usar private_key)",
                    },
                    "private_key": {
                        "type": "string",
                        "description": "Conteudo da chave privada SSH (opcional se usar password)",
                    },
                    "port": {
                        "type": "integer",
                        "description": "Porta SSH (padrao: 22)",
                        "default": 22,
                    },
                },
                "required": ["hostname", "username"],
            },
        ),
        Tool(
            name="ssh_execute",
            description="Executa um comando no servidor SSH conectado. Mantem o diretorio atual entre comandos.",
            inputSchema={
                "type": "object",
                "properties": {
                    "command": {
                        "type": "string",
                        "description": "Comando bash a ser executado",
                    },
                    "timeout": {
                        "type": "integer",
                        "description": "Timeout em segundos (padrao: 60)",
                        "default": 60,
                    },
                },
                "required": ["command"],
            },
        ),
        Tool(
            name="ssh_upload",
            description="Cria/sobrescreve um arquivo no servidor remoto com o conteudo fornecido.",
            inputSchema={
                "type": "object",
                "properties": {
                    "remote_path": {
                        "type": "string",
                        "description": "Caminho completo do arquivo no servidor",
                    },
                    "content": {
                        "type": "string",
                        "description": "Conteudo do arquivo",
                    },
                },
                "required": ["remote_path", "content"],
            },
        ),
        Tool(
            name="ssh_download",
            description="Le o conteudo de um arquivo do servidor remoto.",
            inputSchema={
                "type": "object",
                "properties": {
                    "remote_path": {
                        "type": "string",
                        "description": "Caminho do arquivo no servidor",
                    },
                },
                "required": ["remote_path"],
            },
        ),
        Tool(
            name="ssh_list",
            description="Lista arquivos e diretorios em um caminho do servidor remoto.",
            inputSchema={
                "type": "object",
                "properties": {
                    "path": {
                        "type": "string",
                        "description": "Caminho a ser listado (padrao: diretorio atual)",
                        "default": ".",
                    },
                },
            },
        ),
        Tool(
            name="ssh_info",
            description="Mostra informacoes sobre a conexao SSH atual.",
            inputSchema={
                "type": "object",
                "properties": {},
            },
        ),
        Tool(
            name="ssh_disconnect",
            description="Encerra a conexao SSH atual.",
            inputSchema={
                "type": "object",
                "properties": {},
            },
        ),
    ]


@app.call_tool()
async def call_tool(name: str, arguments: dict) -> list[TextContent]:
    """Processa chamadas de ferramentas SSH."""
    session = get_session()

    if name == "ssh_connect":
        success, message = session.connect(
            hostname=arguments.get("hostname", ""),
            username=arguments.get("username", ""),
            password=arguments.get("password"),
            private_key=arguments.get("private_key"),
            port=arguments.get("port", 22),
        )
        return [TextContent(type="text", text=message)]

    elif name == "ssh_execute":
        result = session.execute(
            command=arguments.get("command", ""),
            timeout=arguments.get("timeout", 60),
        )

        output_parts = []
        if result["stdout"]:
            output_parts.append(result["stdout"])
        if result["stderr"]:
            output_parts.append(f"[stderr]\n{result['stderr']}")
        if result["exit_code"] != 0:
            output_parts.append(f"\n[exit code: {result['exit_code']}]")

        output = "\n".join(output_parts) if output_parts else "(sem saida)"
        return [TextContent(type="text", text=output)]

    elif name == "ssh_upload":
        success, message = session.upload_file(
            content=arguments.get("content", ""),
            remote_path=arguments.get("remote_path", ""),
        )
        return [TextContent(type="text", text=message)]

    elif name == "ssh_download":
        success, content = session.download_file(
            remote_path=arguments.get("remote_path", ""),
        )
        return [TextContent(type="text", text=content)]

    elif name == "ssh_list":
        success, content = session.list_dir(
            path=arguments.get("path", "."),
        )
        return [TextContent(type="text", text=content)]

    elif name == "ssh_info":
        info = session.get_info()
        return [TextContent(type="text", text=info)]

    elif name == "ssh_disconnect":
        message = session.disconnect()
        return [TextContent(type="text", text=message)]

    else:
        return [TextContent(type="text", text=f"Ferramenta desconhecida: {name}")]


async def main():
    """Inicia o servidor MCP via stdio."""
    async with stdio_server() as (read_stream, write_stream):
        await app.run(read_stream, write_stream, app.create_initialization_options())


if __name__ == "__main__":
    asyncio.run(main())

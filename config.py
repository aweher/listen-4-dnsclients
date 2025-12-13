#!/usr/bin/env python3
"""
Copyright (c) 2025 Ariel S. Weher <ariel@ayuda.la>

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all
copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
SOFTWARE.

Mรณdulo para cargar y gestionar la configuraciรณn del proyecto
"""

import os
import yaml
from typing import Dict, Any, Optional
from pathlib import Path

# Ruta por defecto del archivo de configuraciรณn
DEFAULT_CONFIG_PATH = Path(__file__).parent / "config.yaml"


class Config:
    """Clase para gestionar la configuraciรณn del proyecto"""
    
    def __init__(self, config_path: Optional[str] = None):
        """
        Inicializa la configuraciรณn desde un archivo YAML
        
        Args:
            config_path: Ruta al archivo de configuraciรณn (default: config.yaml en el directorio del proyecto)
        """
        if config_path is None:
            config_path = DEFAULT_CONFIG_PATH
        
        self.config_path = Path(config_path)
        self._config = self._load_config()
    
    def _load_config(self) -> Dict[str, Any]:
        """
        Carga la configuraciรณn desde el archivo YAML
        
        Returns:
            Diccionario con la configuraciรณn
        """
        if not self.config_path.exists():
            # Si no existe, crear un archivo de configuraciรณn por defecto
            default_config = {
                'redis': {
                    'host': 'localhost',
                    'port': 6379,
                    'db': 0,
                    'password': None
                },
                'clickhouse': {
                    'host': 'localhost',
                    'port': 9000,
                    'database': 'dns_monitor',
                    'user': 'default',
                    'password': None
                },
                'sniffer': {
                    'interface': None,
                    'filter': 'port 53'
                },
                'auth': {
                    'users': [
                        {
                            'username': 'admin',
                            'password': 'admin123'
                        }
                    ]
                }
            }
            self._save_config(default_config)
            return default_config
        
        try:
            with open(self.config_path, 'r', encoding='utf-8') as f:
                config = yaml.safe_load(f)
                if config is None:
                    config = {}
                return config
        except Exception as e:
            raise ValueError(f"Error cargando configuraciรณn desde {self.config_path}: {e}")
    
    def _save_config(self, config: Dict[str, Any]):
        """Guarda la configuraciรณn en el archivo YAML"""
        try:
            with open(self.config_path, 'w', encoding='utf-8') as f:
                yaml.dump(config, f, default_flow_style=False, allow_unicode=True, sort_keys=False)
        except Exception as e:
            raise ValueError(f"Error guardando configuraciรณn en {self.config_path}: {e}")
    
    def get_redis_config(self) -> Dict[str, Any]:
        """
        Obtiene la configuraciรณn de Redis
        
        Returns:
            Diccionario con host, port, db, password
        """
        redis_config = self._config.get('redis', {})
        password = redis_config.get('password')
        # Handle password: trim whitespace, preserve None, convert empty string to None
        if password is not None:
            password = str(password).strip()
            password = password if password else None
        
        return {
            'host': redis_config.get('host', 'localhost'),
            'port': redis_config.get('port', 6379),
            'db': redis_config.get('db', 0),
            'password': password
        }
    
    def get_sniffer_config(self) -> Dict[str, Any]:
        """
        Obtiene la configuraciรณn del sniffer
        
        Returns:
            Diccionario con interface y filter
        """
        sniffer_config = self._config.get('sniffer', {})
        return {
            'interface': sniffer_config.get('interface'),
            'filter': sniffer_config.get('filter', 'port 53')
        }
    
    def get_clickhouse_config(self) -> Dict[str, Any]:
        """
        Obtiene la configuraciรณn de ClickHouse
        
        Returns:
            Diccionario con host, port, database, user, password
        """
        clickhouse_config = self._config.get('clickhouse', {})
        password = clickhouse_config.get('password')
        # Handle password: trim whitespace, preserve None, convert empty string to None
        if password is not None:
            password = str(password).strip()
            password = password if password else None
        
        return {
            'host': clickhouse_config.get('host', 'localhost'),
            'port': clickhouse_config.get('port', 9000),
            'database': clickhouse_config.get('database', 'dns_monitor'),
            'user': clickhouse_config.get('user', 'default'),
            'password': password
        }
    
    def get_auth_config(self) -> Dict[str, str]:
        """
        Obtiene la configuraciรณn de autenticaciรณn
        
        Returns:
            Diccionario con username como clave y password como valor
        """
        auth_config = self._config.get('auth', {})
        users = auth_config.get('users', [])
        
        # Convertir lista de usuarios a diccionario
        auth_dict = {}
        for user in users:
            if isinstance(user, dict) and 'username' in user and 'password' in user:
                auth_dict[user['username']] = user['password']
        
        # Si no hay usuarios configurados, usar valores por defecto
        if not auth_dict:
            auth_dict = {
                'admin': 'admin123'
            }
        
        return auth_dict
    
    def update_redis_config(self, host: Optional[str] = None, port: Optional[int] = None,
                           db: Optional[int] = None, password: Optional[str] = None):
        """
        Actualiza la configuraciรณn de Redis
        
        Args:
            host: Host de Redis
            port: Puerto de Redis
            db: Base de datos Redis
            password: Contraseรฑa de Redis
        """
        if 'redis' not in self._config:
            self._config['redis'] = {}
        
        if host is not None:
            self._config['redis']['host'] = host
        if port is not None:
            self._config['redis']['port'] = port
        if db is not None:
            self._config['redis']['db'] = db
        if password is not None:
            self._config['redis']['password'] = password
        
        self._save_config(self._config)
    
    def update_clickhouse_config(self, host: Optional[str] = None, port: Optional[int] = None,
                                 database: Optional[str] = None, user: Optional[str] = None,
                                 password: Optional[str] = None):
        """
        Actualiza la configuraciรณn de ClickHouse
        
        Args:
            host: Host de ClickHouse
            port: Puerto de ClickHouse
            database: Nombre de la base de datos
            user: Usuario de ClickHouse
            password: Contraseรฑa de ClickHouse
        """
        if 'clickhouse' not in self._config:
            self._config['clickhouse'] = {}
        
        if host is not None:
            self._config['clickhouse']['host'] = host
        if port is not None:
            self._config['clickhouse']['port'] = port
        if database is not None:
            self._config['clickhouse']['database'] = database
        if user is not None:
            self._config['clickhouse']['user'] = user
        if password is not None:
            self._config['clickhouse']['password'] = password
        
        self._save_config(self._config)
    
    def update_sniffer_config(self, interface: Optional[str] = None, filter_str: Optional[str] = None):
        """
        Actualiza la configuraciรณn del sniffer
        
        Args:
            interface: Interfaz de red
            filter_str: Filtro BPF
        """
        if 'sniffer' not in self._config:
            self._config['sniffer'] = {}
        
        if interface is not None:
            self._config['sniffer']['interface'] = interface
        if filter_str is not None:
            self._config['sniffer']['filter'] = filter_str
        
        self._save_config(self._config)


# Instancia global de configuraciรณn
_config_instance: Optional[Config] = None


def get_config(config_path: Optional[str] = None) -> Config:
    """
    Obtiene la instancia global de configuraciรณn
    
    Args:
        config_path: Ruta opcional al archivo de configuraciรณn
        
    Returns:
        Instancia de Config
    """
    global _config_instance
    if _config_instance is None or config_path is not None:
        _config_instance = Config(config_path)
    return _config_instance


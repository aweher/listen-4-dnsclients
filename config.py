#!/usr/bin/env python3
"""
Módulo para cargar y gestionar la configuración del proyecto
"""

import os
import yaml
from typing import Dict, Any, Optional
from pathlib import Path

# Ruta por defecto del archivo de configuración
DEFAULT_CONFIG_PATH = Path(__file__).parent / "config.yaml"


class Config:
    """Clase para gestionar la configuración del proyecto"""
    
    def __init__(self, config_path: Optional[str] = None):
        """
        Inicializa la configuración desde un archivo YAML
        
        Args:
            config_path: Ruta al archivo de configuración (default: config.yaml en el directorio del proyecto)
        """
        if config_path is None:
            config_path = DEFAULT_CONFIG_PATH
        
        self.config_path = Path(config_path)
        self._config = self._load_config()
    
    def _load_config(self) -> Dict[str, Any]:
        """
        Carga la configuración desde el archivo YAML
        
        Returns:
            Diccionario con la configuración
        """
        if not self.config_path.exists():
            # Si no existe, crear un archivo de configuración por defecto
            default_config = {
                'redis': {
                    'host': 'localhost',
                    'port': 6379,
                    'db': 0,
                    'password': None
                },
                'sniffer': {
                    'interface': None,
                    'filter': 'port 53'
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
            raise ValueError(f"Error cargando configuración desde {self.config_path}: {e}")
    
    def _save_config(self, config: Dict[str, Any]):
        """Guarda la configuración en el archivo YAML"""
        try:
            with open(self.config_path, 'w', encoding='utf-8') as f:
                yaml.dump(config, f, default_flow_style=False, allow_unicode=True, sort_keys=False)
        except Exception as e:
            raise ValueError(f"Error guardando configuración en {self.config_path}: {e}")
    
    def get_redis_config(self) -> Dict[str, Any]:
        """
        Obtiene la configuración de Redis
        
        Returns:
            Diccionario con host, port, db, password
        """
        redis_config = self._config.get('redis', {})
        return {
            'host': redis_config.get('host', 'localhost'),
            'port': redis_config.get('port', 6379),
            'db': redis_config.get('db', 0),
            'password': redis_config.get('password') if redis_config.get('password') else None
        }
    
    def get_sniffer_config(self) -> Dict[str, Any]:
        """
        Obtiene la configuración del sniffer
        
        Returns:
            Diccionario con interface y filter
        """
        sniffer_config = self._config.get('sniffer', {})
        return {
            'interface': sniffer_config.get('interface'),
            'filter': sniffer_config.get('filter', 'port 53')
        }
    
    def update_redis_config(self, host: Optional[str] = None, port: Optional[int] = None,
                           db: Optional[int] = None, password: Optional[str] = None):
        """
        Actualiza la configuración de Redis
        
        Args:
            host: Host de Redis
            port: Puerto de Redis
            db: Base de datos Redis
            password: Contraseña de Redis
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
    
    def update_sniffer_config(self, interface: Optional[str] = None, filter_str: Optional[str] = None):
        """
        Actualiza la configuración del sniffer
        
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


# Instancia global de configuración
_config_instance: Optional[Config] = None


def get_config(config_path: Optional[str] = None) -> Config:
    """
    Obtiene la instancia global de configuración
    
    Args:
        config_path: Ruta opcional al archivo de configuración
        
    Returns:
        Instancia de Config
    """
    global _config_instance
    if _config_instance is None or config_path is not None:
        _config_instance = Config(config_path)
    return _config_instance


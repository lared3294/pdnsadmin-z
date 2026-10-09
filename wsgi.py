import importlib

# Importamos el módulo con guiones dinámicamente
modulo = importlib.import_module("pdnsadmin-z")

# Extraemos la variable 'app' de Flask
app = modulo.app

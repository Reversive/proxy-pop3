# Proxy POP3
>Concurrent multiplexed non-blocking POP3 proxy server

## Ubicación de los archivos
- En la carpeta /docs se encuentra el informe y los manuales de ambas aplicaciones
- En la carpeta /pop3ctl se encuentra el cliente que implementa el protocolo PMP para comunicarse con el servidor admin
- En la carpeta /pop3filter se encuentra el proxy POP3

## Procedimiento para generar ejecutable
1) Tener en una variable de entorno (CC) el nombre del compilador de C deseado:
```
CC=GCC
```
2) Situarse en la raíz del proyecto
```
cd /proxy-pop3
```
3) Ejecutar:
```
make
```

## Ubicación de los artefactos generados
- En la carpeta /proxy-pop3/pop3ctl se encontrará el archivo ejecutable del cliente con el nombre *pop3ctl.out*
- En la carpeta /proxy-pop3/pop3filter se encontrará el archivo ejecutable del proxy POP3 con el nombre *pop3filter.out*

## Cómo ejecutar los artefactos generados
- Tanto el proxy pop3filter como el cliente PMP se encuentran documentados dentro de la carpeta docs.

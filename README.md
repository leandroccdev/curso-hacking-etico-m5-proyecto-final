# Curso Hacking Ético

## Proyecto final - Módulo 5

Generación de un reporte de pentesting automatizado.

## Tecnologías utilizadas

Las herramientas están programadas en Python 3.13+, se utilizó el módulo venv para la creación de los entornos virtuales, y la generación automatizada del reporte funciona dentro de un contenedor Docker con Ubuntu Noble. De ésta manera, se pudo controlar la ejecución en el equipo del agente revisor (docente, revisor, tutor, etc), haciendo que el código dependiera únicamente de Ubuntu Noble (Linux), evitando la necesidad de soportar múltiples sistemas operativos y ahorrándole un importante tiempo al estudiante.
Adicionalmente se construyó una automatización en Bash, para la creación y lanzamiento del contenedor.

### Etapa 1

Realiza un reconocimiento automatizado de los formularios, elementos hijos con sus respectivos sus atributos, y cabeceras de la respuesta HTTP.
Entrega un reporte a través de la terminal (stdout), y generando tanto un registro detallado de la ejecución, como un log json fácilmente analizable programáticamente.

### Etapa 2

Realiza un escaneo con la herramienta nmap desde Python, entrega un reporte a través de la terminal (stdout) detallando los servicios, sus estados y un posible detalle de su versión para cada host entregado.

### Etapa 3

Se dividió en dos fases, una que prueba inyecciones SQL y otra que prueba inyecciones XSS. Ambas generan un reporte a través de la terminal (stdout), detallando los hallazgos por cada URL y un resumen de ejecución que indica las pruebas realizadas. Éstas pruebas se realizan en función de a un archivo de configuración proporcionado mediante comandos de terminal.

### Etapa 5

Ejecuta las etapas anteriores y procesa la información resultante para generar el reporte automatizado. La carpeta `reportes-ejemplos` contiene ejemplos de reportes generados.

Ejecución

En sistemas Linux con Docker previamente instalado, es posible utilizar la automatización `docker.sh` desde la terminal ejecutando: 

````
./docker.sh run
````

Para otros sistemas, se debe construir la imágen y ejecutar el contenedor manualmente a través de la terminal de la siguiente manera:

``` 
docker build -t “flc-scanner” .
docker run –name “c-flc-scanner” -v “PATH-A”:”/opt/flc-scanner/reportes” 
```

`PATH-A` es la carpeta del sistema host en la que se almacenará el reporte generado.
Una vez terminada la ejecución, se tendrán dos archivos, uno `.html` (visible desde el navegador) y otro `.pdf`.
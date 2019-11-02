'''
    arp.py
    Implementación del protocolo ARP y funciones auxiliares que permiten realizar resoluciones de direcciones IP.
    Autor: Javier Ramos <javier.ramos@uam.es>
    2019 EPS-UAM
'''



from ethernet import *
import logging
import socket
import struct
import fcntl
import time
from threading import Lock
from expiringdict import ExpiringDict

#Semáforo global
globalLock = Lock()
#Dirección de difusión (Broadcast)
broadcastAddr = bytes([0xFF]*6)
#Cabecera ARP común a peticiones y respuestas. Específica para la combinación Ethernet/IP
ARPHeader = bytes([0x00,0x01,0x08,0x00,0x06,0x04])
#longitud (en bytes) de la cabecera común ARP
ARP_HLEN = 6
#Variable que alamacenará que dirección IP se está intentando resolver
requestedIP = None
#Variable que alamacenará que dirección MAC resuelta o None si no se ha podido obtener
resolvedMAC = None
#Variable que alamacenará True mientras estemos esperando una respuesta ARP
awaitingResponse = False

#Variable para proteger la caché
cacheLock = Lock()
#Caché de ARP. Es un diccionario similar al estándar de Python solo que eliminará las entradas a los 10 segundos
cache = ExpiringDict(max_len=100, max_age_seconds=10)


'''
Nombre: getIP
Descripción: Esta función obtiene la dirección IP asociada a una interfaz. Esta funció NO debe ser modificada
Argumentos:
   -interface: nombre de la interfaz
Retorno: Entero de 32 bits con la dirección IP de la interfaz
'''
def getIP(interface):
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    ip = fcntl.ioctl(
        s.fileno(),
        0x8915,  # SIOCGIFADDR
        struct.pack('256s', (interface[:15].encode('utf-8')))
    )[20:24]
    s.close()
    return struct.unpack('!I',ip)[0]


'''
Nombre: printCache
Descripción: Esta función imprime la caché ARP
Argumentos: Ninguno
Retorno: Ninguno
'''
def printCache():

    print('{:>12}\t\t{:>12}'.format('IP','MAC'))
    with cacheLock:
        for k in cache:
            if k in cache:
                print ('{:>12}\t\t{:>12}'.format(socket.inet_ntoa(struct.pack('!I',k)),':'.join(['{:02X}'.format(b) for b in cache[k]])))




'''
Nombre: processARPRequest
Decripción: Esta función procesa una petición ARP. Esta función debe realizar, al menos, las siguientes tareas:
    -Extraer la MAC origen contenida en la petición ARP
    -Si la MAC origen de la trama ARP no es la misma que la recibida del nivel Ethernet retornar
    -Extraer la IP origen contenida en la petición ARP
    -Extraer la IP destino contenida en la petición ARP
    -Comprobar si la IP destino de la petición ARP es la propia IP:
        -Si no es la propia IP retornar
        -Si es la propia IP:
            -Construir una respuesta ARP llamando a createARPReply (descripción más adelante)
            -Enviar la respuesta ARP usando el nivel Ethernet (sendEthernetFrame)
Argumentos:
    -data: bytearray con el contenido de la trama ARP (después de la cabecera común)
    -MAC: dirección MAC origen extraída por el nivel Ethernet
Retorno: Ninguno
'''
def processARPRequest(data, MAC):

    global myIP
    # Del byte 0 al 5 es la direccion MAC de origen suponiendo que este sea el primer campo de la parte no comun
    mac_origen = data[:6]
    if mac_origen != MAC:
        return

    # del byte 6 al 10 (10 no incluido) esta la ip origen
    ip_origen = data[6:10]

    # del byte 16 al 20 (20 no incluido) esta la ip destino
    ip_destino = data[16:20]

    # Comprobamos con la variable local
    if ip_destino != myIP:
        return

    # TODO revisar que esta bien
    createARPReply(ip_origen, mac_origen)
    sendEthernetFrame(data, len, data, mac_origen)
    return


'''
Nombre: processARPReply
Decripción: Esta función procesa una respuesta ARP. Esta función debe realizar, al menos, las siguientes tareas:
    -Extraer la MAC origen contenida en la petición ARP
    -Si la MAC origen de la trama ARP no es la misma que la recibida del nivel Ethernet retornar
    -Extraer la IP origen contenida en la petición ARP
    -Extraer la MAC destino contenida en la petición ARP
    -Extraer la IP destino contenida en la petición ARP
    -Comprobar si la IP destino de la petición ARP es la propia IP:
        -Si no es la propia IP retornar
        -Si es la propia IP:
            -Comprobar si la IP origen se corresponde con la solicitada (requestedIP). Si no se corresponde retornar
            -Copiar la MAC origen a la variable global resolvedMAC
            -Añadir a la caché ARP la asociación MAC/IP.
            -Cambiar el valor de la variable awaitingResponse a False
            -Cambiar el valor de la variable requestedIP a None
Las variables globales (requestedIP, awaitingResponse y resolvedMAC) son accedidas concurrentemente por la función ARPResolution y deben ser protegidas mediante un Lock.
Argumentos:
    -data: bytearray con el contenido de la trama ARP (después de la cabecera común)
    -MAC: dirección MAC origen extraída por el nivel Ethernet
Retorno: Ninguno
'''
def processARPReply(data,MAC):

    global requestedIP,resolvedMAC,awaitingResponse,cache, myIP

    # Del byte 0 al 5 es la direccion MAC de origen suponiendo que este sea el primer campo de la parte no comun
    mac_origen = data[:6]
    if mac_origen != MAC:
        return

    # del byte 6 al 10 (10 no incluido) esta la ip origen, la de origen en una arp reply es la que queriamos resolver
    ip_origen = data[6:10]

    # extraemos la mac destino del bytearray (6 bytes sin contar el 26), la que envio la arp request
    mac_destino = data[20:26]

    # del byte 16 al 20 (20 no incluido) esta la ip destino
    ip_destino = data[16:20]

    if ip_destino != myIP:
        return

    if ip_origen != requestedIP:
        return

    # Protegemos con lock usando el bloque with
    with globalLock:
        resolvedMAC = mac_origen

    with cacheLock:
        cache = {ip_origen: mac_origen}
    # aniadimos el par ip/mac , son las de origen porque el arp reply tiene como origen las de destino del arp request

    awaitingResponse = False
    requestedIP = None

    return

'''
Nombre: createARPRequest
Descripción: Esta función construye una petición ARP y devuelve la trama con el contenido.
Argumentos:
    -ip: dirección a resolver
Retorno: Bytes con el contenido de la trama de petición ARP
'''
def createARPRequest(ip):

    global myMAC,myIP

    # falta la parte de la cabecera comun (type of hardware etc)
    # no se si hay que enviarla a [0xFF]*6 o a [0x00]*6 porque es una request
    framechar = str(myMAC) + str(myIP) + str([0xFF]*6) + str(ip)
    frame = bytes(framechar)

    return frame


'''
Nombre: createARPReply
Descripción: Esta función construye una respuesta ARP y devuelve la trama con el contenido.
Argumentos:
    -IP: dirección IP a la que contestar
    -MAC: dirección MAC a la que contestar
Retorno: Bytes con el contenido de la trama de petición ARP
'''
def createARPReply(IP,MAC):

    global myMAC,myIP

    # falta la parte de la cabecera comun (type of hardware etc)
    framechar = str(myMAC) + str(myIP) + str(MAC) + str(IP)
    frame = bytes(framechar)

    return frame


'''
Nombre: process_arp_frame
Descripción: Esta función procesa las tramas ARP.
Se ejecutará por cada trama Ethenet que se reciba con Ethertype 0x0806 (si ha sido registrada en initARP).
Esta función debe realizar, al menos, las siguientes tareas:
    -Extraer la cabecera común de ARP (6 primeros bytes) y comprobar que es correcta
    -Extraer el campo opcode
    -Si opcode es 0x0001 (Request) llamar a processARPRequest (ver descripción más adelante)
    -Si opcode es 0x0002 (Reply) llamar a processARPReply (ver descripción más adelante)
    -Si es otro opcode retornar de la función
    -En caso de que no exista retornar
Argumentos:
    -us: Datos de usuario pasados desde la llamada de pcap_loop. En nuestro caso será None
    -header: cabecera pcap_pktheader
    -data: array de bytes con el contenido de la trama ARP
    -srcMac: MAC origen de la trama Ethernet que se ha recibido
Retorno: Ninguno
'''
def process_arp_frame(us,header,data,srcMac):

    comun = data[:6]
    # comprobar que sea correcta

    opcode = data[6:12]

    # si es una request
    if (opcode == 1):
        processARPRequest(data[6:], srcMac)
    # si es una reply
    elif (opcode == 1):
        processARPReply(data[6:], srcMac)
    else:
        return



'''
Nombre: initARP
Descripción: Esta función construirá inicializará el nivel ARP. Esta función debe realizar, al menos, las siguientes tareas:
    -Registrar la función del callback process_arp_frame con el Ethertype 0x0806
    -Obtener y almacenar la dirección MAC e IP asociadas a la interfaz especificada
    -Realizar una petición ARP gratuita y comprobar si la IP propia ya está asignada. En caso positivo se debe devolver error.
    -Marcar la variable de nivel ARP inicializado a True
'''
def initARP(interface):

    global myIP,myMAC,arpInitialized
    
    # Registramos el callback de process_arp_frame con el Ethertypo 0806
    registerCallback(process_arp_frame, 0806)

    # Obtenemos la mac y la ip asociadas con la interfaz y las almacenamos en la variable global
    myIP = getIP(interface)
    myMAC = getHwAddr(interface)

    # Resolucion ARP gratuita (con nuestra propia IP). Si no se recibe None es que algo ha ido mal
    if ARPResolution(myIP) in not None:
    	logging.debug('ERROR. El ARP ya estaba inicializado')
    	return -1

    # El nivel ARP esta inicializado
    arpInitialized = True
    return 0

'''
Nombre: ARPResolution
Descripción: Esta función intenta realizar una resolución ARP para una IP dada y devuelve la dirección MAC asociada a dicha IP
o None en caso de que no haya recibido respuesta. Esta función debe realizar, al menos, las siguientes tareas:
    -Comprobar si la IP solicitada existe en la caché:
    -Si está en caché devolver la información de la caché
    -Si no está en la caché:
        -Construir una petición ARP llamando a la función createARPRequest (descripción más adelante)
        -Enviar dicha petición
        -Comprobar si se ha recibido respuesta o no:
            -Si no se ha recibido respuesta reenviar la petición hasta un máximo de 3 veces. Si no se recibe respuesta devolver None
            -Si se ha recibido respuesta devolver la dirección MAC
Esta función necesitará comunicarse con el la función de recepción (para comprobar si hay respuesta y la respuesta en sí) mediante 3 variables globales:
    -awaitingResponse: indica si está True que se espera respuesta. Si está a False quiere decir que se ha recibido respuesta
    -requestedIP: contiene la IP por la que se está preguntando
    -resolvedMAC: contiene la dirección MAC resuelta (en caso de que awaitingResponse) sea False.
Como estas variables globales se leen y escriben concurrentemente deben ser protegidas con un Lock
'''
def ARPResolution(ip):

    global requestedIP,awaitingResponse,resolvedMAC
    

    # Si esta en la cache, se devuelve la MAC y listo.
    # Protegemos con semaforo
    with cacheLock:
    	if ip in cache:
    		return cache[ip]

    # En el caso de que no este en la cache enviamos un ARPRequest hasta 3 veces esperando conseguir una respuesta
    # Primero construimos el ARPRequest
    createARPRequest(ip)

    # Le damos valor a las variables globales
    awaitingResponse = True
    requestedIP = ip


    for i in range(3):
    	# Si se sigue esperando respuesta reenviamos el Request
    	if awaitingResponse is True:
    		createARPRequest(ip):

    	# Si se ha recibido respuesta y es la MAC de la IP por la que preguntabamos
    	elsif requestedIP is ip:
    		return resolvedMAC

    return None

'''
    arp.py
    Implementacion del protocolo ARP y funciones auxiliares que permiten realizar resoluciones de direcciones IP.
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
from time import sleep

#Semaforo global
globalLock = Lock()
#Direccion de difusion (Broadcast)
broadcastAddr = bytes([0xFF]*6)
#Cabecera ARP comun a peticiones y respuestas. Especifica para la combinacion Ethernet/IP
ARPHeader = bytes([0x00,0x01,0x08,0x00,0x06,0x04])
#longitud (en bytes) de la cabecera comun ARP
ARP_HLEN = 6
#Variable que alamacenara que direccion IP se esta intentando resolver
requestedIP = None
#Variable que alamacenara que direccion MAC resuelta o None si no se ha podido obtener
resolvedMAC = None
#Variable que alamacenara True mientras estemos esperando una respuesta ARP
awaitingResponse = False

#Variable para proteger la cachae
cacheLock = Lock()
#Cachae de ARP. Es un diccionario similar al estandar de Python solo que eliminara las entradas a los 10 segundos
cache = ExpiringDict(max_len=100, max_age_seconds=10)


'''
Nombre: getIP
Descripcion: Esta funcion obtiene la direccion IP asociada a una interfaz. Esta funcio NO debe ser modificada
Argumentos:
   -interface: nombre de la interfaz
Retorno: Entero de 32 bits con la direccion IP de la interfaz
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
Descripcion: Esta funcion imprime la cachae ARP
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
Decripcion: Esta funcion procesa una peticion ARP. Esta funcion debe realizar, al menos, las siguientes tareas:
    -Extraer la MAC origen contenida en la peticion ARP
    -Si la MAC origen de la trama ARP no es la misma que la recibida del nivel Ethernet retornar
    -Extraer la IP origen contenida en la peticion ARP
    -Extraer la IP destino contenida en la peticion ARP
    -Comprobar si la IP destino de la peticion ARP es la propia IP:
        -Si no es la propia IP retornar
        -Si es la propia IP:
            -Construir una respuesta ARP llamando a createARPReply (descripcion mas adelante)
            -Enviar la respuesta ARP usando el nivel Ethernet (sendEthernetFrame)
Argumentos:
    -data: bytearray con el contenido de la trama ARP (despuaes de la cabecera comun)
    -MAC: direccion MAC origen extraida por el nivel Ethernet
Retorno: Ninguno
'''
def processARPRequest(data, MAC):

    global myIP
    # Del byte 0 al 5 es la direccion MAC de origen suponiendo que este sea el primer campo de la parte no comun
    
    mac_origen = data[2:8]
    
    # print("\n\nMAC ORIGEN:")
    # print(MAC)
    # print("YO PILLO: ")
    # print(mac_origen)
    
    if mac_origen != MAC:
    	
    	return

    # del byte 6 al 10 (10 no incluido) esta la ip origen
    ip_origen = data[8:12]

    # del byte 16 al 20 (20 no incluido) esta la ip destino
    ip_destino = data[18:22]

    myIPBien = struct.pack('!I', myIP)
    print(data)
    print(ip_origen)
    print(myIPBien)
    # Comprobamos con la variable local
    if ip_destino != myIPBien:
    	return
    # TODO revisar que esta bien
    frame = createARPReply(ip_origen, mac_origen)

    sendEthernetFrame(frame, len(frame), bytes([0x08,0x06]), mac_origen)
    return


'''
Nombre: processARPReply
Decripcion: Esta funcion procesa una respuesta ARP. Esta funcion debe realizar, al menos, las siguientes tareas:
    -Extraer la MAC origen contenida en la peticion ARP
    -Si la MAC origen de la trama ARP no es la misma que la recibida del nivel Ethernet retornar
    -Extraer la IP origen contenida en la peticion ARP
    -Extraer la MAC destino contenida en la peticion ARP
    -Extraer la IP destino contenida en la peticion ARP
    -Comprobar si la IP destino de la peticion ARP es la propia IP:
        -Si no es la propia IP retornar
        -Si es la propia IP:
            -Comprobar si la IP origen se corresponde con la solicitada (requestedIP). Si no se corresponde retornar
            -Copiar la MAC origen a la variable global resolvedMAC
            -Annadir a la cachae ARP la asociacion MAC/IP.
            -Cambiar el valor de la variable awaitingResponse a False
            -Cambiar el valor de la variable requestedIP a None
Las variables globales (requestedIP, awaitingResponse y resolvedMAC) son accedidas concurrentemente por la funcion ARPResolution y deben ser protegidas mediante un Lock.
Argumentos:
    -data: bytearray con el contenido de la trama ARP (despuaes de la cabecera comun)
    -MAC: direccion MAC origen extraida por el nivel Ethernet
Retorno: Ninguno
'''
def processARPReply(data,MAC):

    global requestedIP,resolvedMAC,awaitingResponse,cache, myIP
    # Del byte 0 al 5 es la direccion MAC de origen suponiendo que este sea el primer campo de la parte no comun
    mac_origen = data[2:8]

    
    if mac_origen != MAC:
        return

    # del byte 6 al 10 (10 no incluido) esta la ip origen, la de origen en una arp reply es la que queriamos resolver

    # extraemos la mac destino del bytearray (6 bytes sin contar el 26), la que envio la arp request
    mac_destino = data[18:24]

    


    # del byte 16 al 20 (20 no incluido) esta la ip destino
    ip_destino = data[18:22]

    ip_origen = data[8:12]

    myIPBien = struct.pack('!I', myIP)

    if ip_destino != myIPBien:
        print("ERROR1")
        return

    if ip_origen != struct.pack('!I', requestedIP):
    	print("ERROR2")
    	return

    # Protegemos con lock usando el bloque with
    with globalLock:
        resolvedMAC = mac_origen

    with cacheLock:
        cache = {requestedIP: mac_origen}
    # aniadimos el par ip/mac , son las de origen porque el arp reply tiene como origen las de destino del arp request
    with globalLock:
        awaitingResponse = False

    return

'''
Nombre: createARPRequest
Descripcion: Esta funcion construye una peticion ARP y devuelve la trama con el contenido.
Argumentos:
    -ip: direccion a resolver
Retorno: Bytes con el contenido de la trama de peticion ARP
'''
def createARPRequest(ip):

    global myMAC,myIP

    # falta la parte de la cabecera comun (type of hardware etc)
    # no se si hay que enviarla a [0xFF]*6 o a [0x00]*6 porque es una request
    frame = myMAC + bytes(struct.pack('!I', myIP)) + broadcastAddr + bytes(struct.pack('!I', ip))
    
    # print("framechar: "+framechar)
    # Necesario el encoding

    # frame = bytes(framechar, encoding='utf8')
    # print("frame: "+str(frame))
    frame = ARPHeader + bytes([0x00,0x01]) + frame

    return frame


'''
Nombre: createARPReply
Descripcion: Esta funcion construye una respuesta ARP y devuelve la trama con el contenido.
Argumentos:
    -IP: direccion IP a la que contestar
    -MAC: direccion MAC a la que contestar
Retorno: Bytes con el contenido de la trama de peticion ARP
'''
def createARPReply(IP,MAC):

    global myMAC,myIP

    # falta la parte de la cabecera comun (type of hardware etc)
    frame = myMAC + bytes(struct.pack('!I', myIP)) + MAC + IP
    

    frame = ARPHeader + bytes([0x00,0x02]) + frame
    
    return frame


'''
Nombre: process_arp_frame
Descripcion: Esta funcion procesa las tramas ARP.
Se ejecutara por cada trama Ethenet que se reciba con Ethertype 0x0806 (si ha sido registrada en initARP).
Esta funcion debe realizar, al menos, las siguientes tareas:
    -Extraer la cabecera comun de ARP (6 primeros bytes) y comprobar que es correcta
    -Extraer el campo opcode
    -Si opcode es 0x0001 (Request) llamar a processARPRequest (ver descripcion mas adelante)
    -Si opcode es 0x0002 (Reply) llamar a processARPReply (ver descripcion mas adelante)
    -Si es otro opcode retornar de la funcion
    -En caso de que no exista retornar
Argumentos:
    -us: Datos de usuario pasados desde la llamada de pcap_loop. En nuestro caso sera None
    -header: cabecera pcap_pktheader
    -data: array de bytes con el contenido de la trama ARP
    -srcMac: MAC origen de la trama Ethernet que se ha recibido
Retorno: Ninguno
'''
def process_arp_frame(us,header,data,srcMac):

	comun = data[:6]
    # comprobar que sea correcta
	if comun != ARPHeader:
		print ("La cabecera comun no es correcta")
	opcode = data[6:8]

    # si es una request
	if (opcode == bytes([0x00,0x01])):
		processARPRequest(data[6:], srcMac)
    # si es una reply
	elif (opcode == bytes([0x00,0x02])):
		processARPReply(data[6:], srcMac)
	else:
		return



'''
Nombre: initARP
Descripcion: Esta funcion construira inicializara el nivel ARP. Esta funcion debe realizar, al menos, las siguientes tareas:
    -Registrar la funcion del callback process_arp_frame con el Ethertype 0x0806
    -Obtener y almacenar la direccion MAC e IP asociadas a la interfaz especificada
    -Realizar una peticion ARP gratuita y comprobar si la IP propia ya esta asignada. En caso positivo se debe devolver error.
    -Marcar la variable de nivel ARP inicializado a True
'''
def initARP(interface):

    global myIP,myMAC,arpInitialized
    
    # Registramos el callback de process_arp_frame con el Ethertypo 0806
    registerCallback(process_arp_frame, bytes([0x08,0x06]))

    # Obtenemos la mac y la ip asociadas con la interfaz y las almacenamos en la variable global
    myIP = getIP(interface)
    myMAC = getHwAddr(interface)

    # Resolucion ARP gratuita (con nuestra propia IP). Si no se recibe None es que algo ha ido mal
    prueba = ARPResolution(myIP)
    print(prueba)
    if prueba is not None:
    	logging.debug('ERROR. El ARP ya estaba inicializado')
    	return False

    # El nivel ARP esta inicializado
    arpInitialized = True
    return True

'''
Nombre: ARPResolution
Descripcion: Esta funcion intenta realizar una resolucion ARP para una IP dada y devuelve la direccion MAC asociada a dicha IP
o None en caso de que no haya recibido respuesta. Esta funcion debe realizar, al menos, las siguientes tareas:
    -Comprobar si la IP solicitada existe en la cachae:
    -Si esta en cachae devolver la informacion de la cachae
    -Si no esta en la cachae:
        -Construir una peticion ARP llamando a la funcion createARPRequest (descripcion mas adelante)
        -Enviar dicha peticion
        -Comprobar si se ha recibido respuesta o no:
            -Si no se ha recibido respuesta reenviar la peticion hasta un maximo de 3 veces. Si no se recibe respuesta devolver None
            -Si se ha recibido respuesta devolver la direccion MAC
Esta funcion necesitara comunicarse con el la funcion de recepcion (para comprobar si hay respuesta y la respuesta en si) mediante 3 variables globales:
    -awaitingResponse: indica si esta True que se espera respuesta. Si esta a False quiere decir que se ha recibido respuesta
    -requestedIP: contiene la IP por la que se esta preguntando
    -resolvedMAC: contiene la direccion MAC resuelta (en caso de que awaitingResponse) sea False.
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

    # Le damos valor a las variables globales
    with globalLock:
        awaitingResponse = True
        requestedIP = ip

    data = createARPRequest(ip)
    
    for i in range(3):
    	# Si se sigue esperando respuesta reenviamos el Request
        if awaitingResponse is True:
    		# print("bytearray: "+str(bytes([0x08,0x06])))
            sendEthernetFrame(data, len(data), bytes([0x08,0x06]), broadcastAddr)
            print("pregunto por:")
            print(ip)
            sleep(1)
    		# print("La requestedIP es: "+str(requestedIP))
    		# print("lo que he enciado es:"+str(data))

    	# Si se ha recibido respuesta y es la MAC de la IP por la que preguntabamos
        else:
            print("resolvido")
            return resolvedMAC
    
    return None

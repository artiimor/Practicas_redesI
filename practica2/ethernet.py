'''
    ethernet.py
    Implementacion del nivel Ethernet y funciones auxiliares para el envio y recepcion de tramas Ethernet
    Autor: Javier Ramos <javier.ramos@uam.es>
    2019 EPS-UAM
'''

from rc1_pcap import *
import logging
import socket
import struct
from binascii import hexlify
import struct
import threading

#Tamanno maximo de una trama Ethernet (para las practicas)
ETH_FRAME_MAX = 1514
#Tamanno minimo de una trama Ethernet
ETH_FRAME_MIN = 60
PROMISC = 1
NO_PROMISC = 0
TO_MS = 10
#Direccion de difusion (Broadcast)
broadcastAddr = bytes([0xFF]*6)
#Diccionario que alamacena para un Ethertype dado que funcion de callback se debe ejecutar
upperProtos = {}


'''
Nombre: getHwAddrcallback
Descripcion: Esta funcion obtiene la direccion MAC asociada a una interfaz
Argumentos:
    -interface: Cadena con el nombre de la interfaz
Retorno:
    -Direccion MAC de la itnerfaz
'''
def getHwAddr(interface):
    s = socket.socket(socket.AF_PACKET, socket.SOCK_RAW)
    s.bind((interface,0))
    mac =  (s.getsockname()[4])
    s.close()
    return mac

'''
Nombre: process_Ethernet_frame
Descripcion: Esta funcion se ejecutara cada vez que llegue una trama Ethernet.
    Esta funcion debe realizar, al menos, las siguientes tareas:
        -Extraer los campos de direccion Ethernet destino, origen y ethertype
        -Comprobar si la direccion destino es la propia o la de broadcast. En caso de que la trama no vaya en difusion o no sea para nuestra interfaz la descartaremos (haciendo un return).
        -Comprobar si existe una funcion de callback de nivel superior asociada al Ethertype de la trama:
            -En caso de que exista, llamar a la funcion de nivel superior con los parametros que corresponde:
                -us (datos de usuario)
                -header (cabecera pcap_pktheader)
                -payload (datos de la trama excluyendo la cabecera Ethernet)
                -direccion Ethernet origen
            -En caso de que no exista retornar
Argumentos:
    -us: datos de usuarios pasados desde pcap_loop (en nuestro caso sera None)
    -header: estructura pcap_pkthdr que contiene los campos len, caplen y ts.
    -data: bytearray con el contenido de la trama Ethernet
Retorno:
    -Ninguno
'''
def process_Ethernet_frame(us,header,data):
	global macAddress
	data = bytes(data)
    # Ethernet origen los 6 primeros bytes
	ethernet_origen = data[:6]
	# print('PUTA VIDA')
	# Ethernet destino del 6 al 12
	ethernet_destino = data[6:12]

    # Ethertype los dos siguientes bytes
	ethertype = data [12:14]

    # Comprobamos si el destino somos nosotros o el broadcastAddr
    
	if ethernet_destino != macAddress and ethernet_destino != broadcastAddr:
		return
    # print("El ethertype es: "+str(ethertype))
    # print(ethernet_origen)
	if not str(bytes(ethertype)) in upperProtos:
		# print("No se ha encontrado el ethertype: "+str(ethertype)+"en el diccionario")
		# print(upperProtos)
		return
    
	func = upperProtos[str(bytes(ethertype))]
	
	func (us, header, data[14:], ethernet_origen)


'''
Nombre: process_frame
Descripcion: Esta funcion se pasa a pcap_loop y se ejecutara cada vez que llegue una trama. La funcion
ejecutara la funcion process_Ethernet_frame en un hilo nuevo para evitar interbloqueos entre 2 recepciones
consecutivas de tramas dependientes. Esta funcion NO debe modifciarse
Argumentos:
    -us: datos de usuarios pasados desde pcap_loop (en nuestro caso sera None)
    -header: estructura pcap_pkthdr que contiene los campos len, caplen y ts.
    -data: bytearray con el contenido de la trama Ethernet
Retorno:
    -Ninguno
'''
def process_frame(us,header,data):

    threading.Thread(target=process_Ethernet_frame,args=(us,header,data)).start()


'''
Clase que implementa un hilo de recepcion. De esta manera al iniciar el nivel Ethernet
podemos dejar un hilo con pcap_loop que reciba los paquetes sin bloquear el envio.
En esta clase NO se debe modificar codigo
'''
class rxThread(threading.Thread):

    def __init__(self):
        threading.Thread.__init__(self)

    def run(self):
        global handle
        # Ejecuta pcap_loop. OJO: handle debe estar inicializado con el resultado de pcap_open_live
        if handle is not None:
            pcap_loop(handle,-1,process_frame,None)
    def stop(self):
        global handle
        # Para la ejecucion de pcap_loop
        if handle is not None:
            pcap_breakloop(handle)


'''
Nombre: registerCallback
Descripcion: Esta funcion recibira el nombre de una funcion y su valor de ethertype asociado y annadira en la tabla
    (diccionario) de protocolos de nivel superior el dicha asociacion.
    Este mecanismo nos permite saber a que funcion de nivel superior debemos llamar al recibir una trama de determinado tipo.
    Por ejemplo, podemos registrar una funcion llamada process_IP_datagram asociada al Ethertype 0x0800 y otra llamada process_arp_packet
    asocaida al Ethertype 0x0806.
Argumentos:
    -callback_fun: funcion de callback a ejecutar cuando se reciba el Ethertype especificado.
        La funcion que se pase como argumento debe tener el siguiente prototipo: funcion(us,header,data,srcMac)
        Donde:
            -us: son los datos de usuarios pasados por pcap_loop (en nuestro caso este valor sera siempre None)
            -header: estructura pcap_pkthdr que contiene los campos len, caplen y ts.
            -data: payload de la trama Ethernet. Es decir, la cabecera Ethernet NUNCA se pasa hacia arriba.
            -srcMac: direccion MAC que ha enviado la trama actual.
        La funcion no retornara nada. Si una trama se quiere descartar basta con hacer un return sin valor y dejara de procesarse.
    -ethertype: valor de Ethernetype para el cual se quiere registrar una funcion de callback.
Retorno:
	Ninguno
'''
def registerCallback(callback_func, ethertype):

    global upperProtos
    #upperProtos es el diccionario que relaciona funcion de callback y ethertype
    upperProtos[ethertype] = callback_func


'''
Nombre: startEthernetLevel
Descripcion: Esta funcion recibe el nombre de una interfaz de red e inicializa el nivel Ethernet.
    Esta funcion debe realizar , al menos, las siguientes tareas:
        -Comprobar si el nivel Ethernet ya estaba inicializado (mediante una variable global). Si ya estaba inicializado devolver -1.
        -Obtener y almacenar en una variable global la direccion MAC asociada a la interfaz que se especifica
        -Abrir la interfaz especificada en modo promiscuo usando la libreria rc1-pcap
        -Arrancar un hilo de recepcion (rxThread) que llame a la funcion pcap_loop.
        -Si todo es correcto marcar la variable global de nivel incializado a True
Argumentos:
    -Interface: nombre de la interfaz sobre la que inicializar el nivel Ethernet
Retorno: 0 si todo es correcto, -1 en otro caso
'''
def startEthernetLevel(interface):

    global macAddress, handle, levelInitialized, recvThread
    handle = None
    errbuf = bytearray()

    # Comprobamos parametros
    if interface is None:
        return -1

     # Comprobamos si esta inicializado
    #if levelInitialized is True:
    #    return -1

    # Almacenamos la direccion MAC de la interfaz
    macAddress = getHwAddr(interface)

    # Abrimos la interfaz en modo promiscuo con la libreria pcap
    handle = pcap_open_live(interface, ETH_FRAME_MAX, PROMISC, TO_MS, errbuf)

    # Control de errores
    if handle is None:
        return -1

    # Ahora el nivel SI esta inicializado
    levelInitialized = True

    # Una vez hemos abierto la interfaz para captura y hemos inicializado las variables globales
    # (macAddress, handle y levelInitialized) arrancamos el hilo de recepcion

    # TODO comprobar esto por si acaso
    recvThread = rxThread()
    recvThread.daemon = True
    recvThread.start()
    return 0


global macAddress, handle, levelInitialized, recvThread
'''
Nombre: stopEthernetLevel
Descripcion_ Esta funcion parara y liberara todos los recursos necesarios asociados al nivel Ethernet.
    Esta funcion debe realizar, al menos, las siguientes tareas:
        -Parar el hilo de recepcion de paquetes
        -Cerrar la interfaz (handle de pcap)
        -Marcar la variable global de nivel incializado a False
Argumentos: Ninguno
Retorno: 0 si todo es correcto y -1 en otro caso
'''
def stopEthernetLevel():

    # Paramos el hilo de recepcion
    recvThread.stop()

    # cerramos el descriptor
    if handle is not None:
        pcap_close(handle)

    # Ahora el nivel no esta inicializado
    levelInitialized = False
    return 0



'''
Nombre: sendEthernetFrame
Descripcion: Esta funcion construira una trama Ethernet con lo datos recibidos y la enviara por la interfaz de red.
    Esta funcion debe realizar, al menos, las siguientes tareas:
        -Construir la trama Ethernet a enviar (incluyendo cabecera + payload). Los campos propios (por ejemplo la direccion Ethernet origen)
            deben obtenerse de las variables que han sido inicializadas en startEthernetLevel
        -Comprobar los limites de Ethernet. Si la trama es muy pequenna se debe rellenar con 0s mientras que
            si es muy grande se debe devolver error.
        -Llamar a pcap_inject para enviar la trama y comprobar el retorno de dicha llamada. En caso de que haya error notificarlo
Argumentos:
    -data: datos utiles o payload a encapsular dentro de la trama Ethernet
    -len: longitud de los datos utiles expresada en bytes
    -etherType: valor de tipo Ethernet a incluir en la trama
    -dstMac: Direccion MAC destino a incluir en la trama que se enviara
Retorno: 0 si todo es correcto, -1 en otro caso
'''
def sendEthernetFrame(data,len,etherType,dstMac):

    global macAddress,handle

    s = socket.socket(socket.AF_PACKET, socket.SOCK_RAW)

    # La trama ethernet que construyo esta constituida por la siguiente secuencia de bytes:
    # 6 bytes de la direccion MAC de origen
    # 6 bytes de la direccion MAC de destino
    # 2 bytes de la cabecera ethertype
    # el resto de bytes es el payload

    # Primero comprobar que la cabecera no va a ser de longitud mayor que la permitida



    if len > ETH_FRAME_MAX:
    	logging.debug('Se ha intentado crear una cabecera ethernet con longitud mayor de lo permitido.')
    	return -1

    # Si la trama ethernet no se pasa de tamanno la construyo
    ethernetFrame = macAddress + dstMac + etherType + data
    
    len = len + 2 + 6 +6

    # print("manAddress: "+str(macAddress))
    # print("dstMAC: "+str(dstMac))
    # print("ethertype: "+str(etherType))
    # print("data: "+str(data))
    # print("ethernet frame: "+str(ethernetFrame))
    # Si la trama es demasiado corta la relleno con ceros
    
    if len < ETH_FRAME_MIN:
    	
    	ethernetFrame = ethernetFrame + bytes([0]*(ETH_FRAME_MIN-len))
    	len = ETH_FRAME_MIN
    	# print("\n\nFRAME de puta madre: \n")
    	# print(ethernetFrame)
    	

    # Por ultimo, llamo a pcap inject
    pcap_inject(handle, ethernetFrame, len)

    return 0

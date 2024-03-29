import socket
import struct

import binascii
import functools


import logging
from arp import *
from ethernet import *
from fcntl import ioctl
import subprocess

SIOCGIFMTU = 0x8921
SIOCGIFNETMASK = 0x891b
#Diccionario de protocolos. Las claves con los valores numéricos de protocolos de nivel superior a IP
#por ejemplo (1, 6 o 17) y los valores son los nombres de las funciones de callback a ejecutar.
protocols={}
#Valor inicial para el IPID
IPID = 0
#Valor de ToS por defecto
DEFAULT_TOS = 0
#Tamaño mínimo de la cabecera IP
IP_MIN_HLEN = 20
#Tamaño máximo de la cabecera IP
IP_MAX_HLEN = 60
#Valor de TTL por defecto
DEFAULT_TTL = 64

def chksum(msg):
    '''
        Nombre: chksum
        Descripción: Esta función calcula el checksum IP sobre unos datos de entrada dados (msg)
        Argumentos:
            -msg: array de bytes con el contenido sobre el que se calculará el checksum
        Retorno: Entero de 16 bits con el resultado del checksum en ORDEN DE RED
    '''
    s = 0       
    for i in range(0, len(msg), 2):
        if (i+1) < len(msg):
            a = msg[i] 
            b = msg[i+1]
            s = s + (a+(b << 8))
        elif (i+1)==len(msg):
            s += msg[i]
        else:
            raise 'Error calculando el checksum'
    s = s + (s >> 16)
    s = ~s & 0xffff

    return s

def getMTU(interface):
    '''
        Nombre: getMTU
        Descripción: Esta función obteiene la MTU para un interfaz dada
        Argumentos:
            -interface: cadena con el nombre la interfaz sobre la que consultar la MTU
        Retorno: Entero con el valor de la MTU para la interfaz especificada
    '''
    s = socket.socket(socket.AF_PACKET, socket.SOCK_RAW)
    ifr = struct.pack('16sH', interface.encode("utf-8"), 0)
    mtu = struct.unpack('16sH', ioctl(s,SIOCGIFMTU, ifr))[1]
   
    s.close()
   
    return mtu
   
def getNetmask(interface):
    '''
        Nombre: getNetmask
        Descripción: Esta función obteiene la máscara de red asignada a una interfaz 
        Argumentos:
            -interface: cadena con el nombre la interfaz sobre la que consultar la máscara
        Retorno: Entero de 32 bits con el valor de la máscara de red
    '''
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    ip = fcntl.ioctl(
        s.fileno(),
       SIOCGIFNETMASK,
        struct.pack('256s', (interface[:15].encode('utf-8')))
    )[20:24]
    s.close()
    return struct.unpack('!I',ip)[0]


def getDefaultGW(interface):
    '''
        Nombre: getDefaultGW
        Descripción: Esta función obteiene el gateway por defecto para una interfaz dada
        Argumentos:
            -interface: cadena con el nombre la interfaz sobre la que consultar el gateway
        Retorno: Entero de 32 bits con la IP del gateway
    '''
    p = subprocess.Popen(['ip r | grep default | awk \'{print $3}\''], stdout=subprocess.PIPE, shell=True)
    dfw = p.stdout.read().decode('utf-8')
    # print(dfw)
    return struct.unpack('!I',socket.inet_aton(dfw))[0]


'''
    Nombre: process_IP_datagram
    Descripción: Esta función procesa datagramas IP recibidos.
        Se ejecuta una vez por cada trama Ethernet recibida con EthertypeipOpts 0x0800
        Esta función debe realizar, al menos, las siguientes tareas:
            -Extraer los campos de la cabecera IP (includa la longitud de la cabecera)
            -Calcular el checksum sobre los bytes de la cabecera IP
                -Comprobar que el resultado del checksum es 0. Si es distinto el datagrama se deja de procesar
            -Analizar los bits de de MF y el offset. Si el offset tiene un valor != 0 dejar de procesar el datagrama (no vamos a reensamblar)
            -Loggear (usando logging.debug) el valor de los siguientes campos:
                -Longitud de la cabecera IP
                -IPID
                -Valor de las banderas DF y MF
                -Valor de offset
                -IP origen y destino
                -Protocolo
            -Comprobar si tenemos registrada una función de callback de nivel superior consultando el diccionario protocols y usando como
            clave el valor del campo protocolo del datagrama IP.
                -En caso de que haya una función de nivel superior registrada, debe llamarse a dicha funciñón 
                pasando los datos (payload) contenidos en el datagrama IP.

    Argumentos:
        -us: Datos de usuario pasados desde la llamada de pcap_loop. En nuestro caso será None
        -header: cabecera pcap_pktheader
        -data: array de bytes con el contenido del datagrama IP
        -srcMac: MAC origen de la trama Ethernet que se ha recibido
    Retorno: Ninguno
'''
def process_IP_datagram(us,header,data,srcMac):

    data = bytes(data)

    # version => 4 primeros bits => XXXX----
    version = data[0] >> 0x04 # Lo desplazo 4 bytes
    # print("VERSION: "+str(version))

    # ihl => 4 ultimos bytes => ----XXXX
    ihl = data[0] & 0x0F # aplico mascara 0000 1111 (0x0f)
    ihl = ihl*4
    # print("ihl: "+str(ihl))
    # TOService es el segundo byte
    ToService = data[1]
    # print("type of service: "+str(ToService))
    # Total lenght son el tercer y cuarto byte
    totalLength = data[2:4]
    # print("Total lenght: "+str(totalLength[0]) +" "+str(totalLength[1]))

    # Identification son el quinto y sexto byte
    identification = data[4:6]
    # print("Identification: "+str(identification[0]) +" "+str(identification[1]))
    # Los 3 primeros bits del septimo byte. Realizamos desplazamiento despues de aplicar la mascara correspondiente
    # Nos interesan el bit 2 y 3 porque el primero esta reservado y es igual a 0
    DF = data[6] & 0x40 # -X-- ---- de data[7]
    DF = DF >> 6 # desplazo 6 a la izquierda => ---- ---X>
    MF = data[6] & 0x20 # --X- ---- de data[7]
    MF = MF >> 5 # desplazo 5 a la izquierda => ---- ---X>
    # print("DF: "+str(DF))
    # print("MF: "+str(MF))

    # Offset es el resto del septimo byte y el octavo => ---X XXXX 
    offset=int(binascii.hexlify(data[6:8]),16) & 0x1F

    print("\n\n\n")
    print(offset)
    print("\n\n\n")
    # print("offset: "+str(offset))
    # time to live es el noveno byte
    TtoLive = data[8]
    # print("Time to live: "+str(TtoLive))

    # protocol es el decimo byte
    protocol = data[9]
    # print("protocol "+str(protocol))

    # Header Checksum son los bytes 11 y 12
    HChecksum = data[10:12]
    # print("Checksum de su pùta madre: "+str(HChecksum))

    # Las direcciones ip origen y destino ocupan 4 bytes y vienen a continuacion
    iporigen = data[12:16]
    # print("IP ORIGEN: "+str(iporigen[0]) + " " +str(iporigen[1]) + " "+str(iporigen[2]) + " "+str(iporigen[3]) + " ")
    ipdestino = data[16:20]
    # print("IP DESTINO: "+str(ipdestino[0]) + " " +str(ipdestino[1]) + " "+str(ipdestino[2]) + " "+str(ipdestino[3]) + " ")

    # Faltan por extraer las opciones y el padding que vienen a continuacion

    # print(data[:ihl])
    checksum = chksum(data[:ihl])
    # print(checksum)
    # print(HChecksum)

    # si el checksum no es 0 retornamos
    # if checksum != 0:
    #    print("MI POLLA")
    #    return

    # Si el offset no es 0 retornamos
    if offset != 0:
        return

    # Realizacion del logueado de los campos pedidos
    logging.debug("Cabecera IP: "+str(ihl))
    logging.debug("IPID: "+str(identification))
    logging.debug("DF flag: "+str(DF))
    logging.debug("MF flaf: "+str(MF))
    logging.debug("offset: "+str(offset))
    logging.debug("IP Origen: "+str(iporigen))
    logging.debug("IP Destino: "+str(ipdestino))
    if protocol  == 1:
        logging.debug("Protocolo: ICMP")
    if protocol == 6:
        logging.debug("Protocolo: IP")
    if protocol == 17:
        logging.debug("Protocolo: UDP")


    if not protocol in protocols:
        logging.debug("No se ha encontrado un protocolo en el diccionario")
        return

    func = protocols[protocol]

    # Llamamos a la funcion pasandole el payload
    # print(data)
    payload = data[ihl:]
    # print(payload)
    func(us, header, payload, iporigen)


'''
        Nombre: registerIPProtocol
        Descripción: Esta función recibirá el nombre de una función y su valor de protocolo IP asociado y añadirá en la tabla 
            (diccionario) de protocolos de nivel superior dicha asociación. 
            Este mecanismo nos permite saber a qué función de nivel superior debemos llamar al recibir un datagrama IP  con un 
            determinado valor del campo protocolo (por ejemplo TCP o UDP).
            Por ejemplo, podemos registrar una función llamada process_UDP_datagram asociada al valor de protocolo 17 y otra 
            llamada process_ICMP_message asocaida al valor de protocolo 1. 
        Argumentos:
            -callback_fun: función de callback a ejecutar cuando se reciba el protocolo especificado. 
                La función que se pase como argumento debe tener el siguiente prototipo: funcion(us,header,data,srcIp):
                Dónde:
                    -us: son los datos de usuarios pasados por pcap_loop (en nuestro caso este valor será siempre None)
                    -header: estructura pcap_pkthdr que contiene los campos len, caplen y ts.
                    -data: payload del datagrama IP. Es decir, la cabecera IP NUNCA se pasa hacia arriba.
                    -srcIP: dirección IP que ha enviado el datagrama actual.
                La función no retornará nada. Si un datagrama se quiere descartar basta con hacer un return sin valor y dejará de procesarse.
            -protocol: valor del campo protocolo de IP para el cuál se quiere registrar una función de callback.
        Retorno: Ninguno 
    '''
def registerIPProtocol(callback,protocol):
    
    protocols[protocol] = callback

'''
        Nombre: initIP
        Descripción: Esta función inicializará el nivel IP. Esta función debe realizar, al menos, las siguientes tareas:
            -Llamar a initARP para inicializar el nivel ARP
            -Obtener (llamando a las funciones correspondientes) y almacenar en variables globales los siguientes datos:
                -IP propia
                -MTU
                -Máscara de red (netmask)
                -Gateway por defecto
            -Almacenar el valor de opts en la variable global ipOpts
            -Registrar a nivel Ethernet (llamando a registerCallback) la función process_IP_datagram con el Ethertype 0x0800
        Argumentos:
            -interface: cadena de texto con el nombre de la interfaz sobre la que inicializar ip
            -opts: array de bytes con las opciones a nivel IP a incluir en los datagramas o None si no hay opciones a añadir
        Retorno: True o False en función de si se ha inicializado el nivel o no
    '''
def initIP(interface,opts=None):
    global myIP, MTU, netmask, defaultGW,ipOpts

    # Llamamos a initARP
    initARP(interface)

    # Almacenamos la informacion en las variables globales
    myIP = getIP(interface)
    MTU = getMTU(interface)
    netmask = getNetmask(interface)
    defaultGW = getDefaultGW(interface)
    ipOpts = opts

    # Registramos el nivel Ethernet
    registerCallback(process_IP_datagram,bytes([0x08,0x00]))
    
'''
        Nombre: sendIPDatagram
        Descripción: Esta función construye un datagrama IP y lo envía. En caso de que los datos a enviar sean muy grandes la función
        debe generar y enviar el número de fragmentos IP que sean necesarios.
        Esta función debe realizar, al menos, las siguientes tareas:
            -Determinar si se debe fragmentar o no y calcular el número de fragmentos
            -Para cada datagrama o fragmento:
                -Construir la cabecera IP con los valores que corresponda.Incluir opciones en caso de que ipOpts sea distinto de None
                -Calcular el checksum sobre la cabecera y añadirlo a la cabecera en la posición correcta
                -Añadir los datos a la cabecera IP
                -En el caso de que sea un fragmento ajustar los valores de los campos MF y offset de manera adecuada
                -Enviar el datagrama o fragmento llamando a sendEthernetFrame. Para determinar la dirección MAC de destino
                al enviar los datagramas:
                    -Si la dirección IP destino está en mi subred:
                        -Realizar una petición ARP para obtener la MAC asociada a dstIP y usar dicha MAC
                    -Si la dirección IP destino NO está en mi subred:
                        -Realizar una petición ARP para obtener la MAC asociada al gateway por defecto y usar dicha MAC
            -Para cada datagrama (no fragmento):
                -Incrementar la variable IPID en 1.
        Argumentos:
            -dstIP: entero de 32 bits con la IP destino del datagrama 
            -data: array de bytes con los datos a incluir como payload en el datagrama
            -protocol: valor numérico del campo IP protocolo que indica el protocolo de nivel superior de los datos
            contenidos en el payload. Por ejemplo 1, 6 o 17.
        Retorno: True o False en función de si se ha enviado el datagrama correctamente o no
          
    '''
def sendIPDatagram(dstIP,data,protocol):
    global IPID
    
    

    if ipOpts is not None:
        ipHeaderLenght = IP_MIN_HLEN + len(ipOpts)
    else:
        ipHeaderLenght = IP_MIN_HLEN

    if ipHeaderLenght > IP_MAX_HLEN:
        logging.debug("ERROR, la cabecerea IP es demasiado grande")
        return Falseindiceopts
     
    

    #####################################################################################
    ########################Calculamos el numero de paquetes#############################
    #####################################################################################


    maxPayloadLenght = 1500 - ipHeaderLenght
    
    while (maxPayloadLenght % 8) != 0:
        maxPayloadLenght -= 1


    numPackages = (len(data) // maxPayloadLenght) # El numero de paquetes es la division entera
    if len(data) % maxPayloadLenght is not 0:
        numPackages += 1 # Si el resto no es 0 tengo que enviar otro paquete con el resto de la informacion

    i = 0
    print("NUMERO DE PAQUETES DE LOS COJONES: "+str(numPackages))

    #####################################################################################
    ########################Creamos y enviamos los paquetes##############################
    #####################################################################################
    while i < numPackages:
        # Me da igual que el programa sea mas ineficiente o lo que pollas pase, no voy a optimizar esto

        header = bytearray()
        # Construimos lo que falta de la cabecera IP
        # Comprobaciones si es el ultimo paquete
        if i == (numPackages-1):
            # Primer byte. version y la longitud total de la cabecera  
            header += ((0x40)+(ipHeaderLenght//4)).to_bytes(1, byteorder='big')
            # Segundo byte. Siempre 0
            header += (0).to_bytes(1, byteorder='big')
            # Su longitud será lo que no hemos enviado del data mas la longitud del header
            header += ((len(data) - (maxPayloadLenght * (numPackages-1))) + ipHeaderLenght).to_bytes(2, byteorder='big')
            # Quinto y sexto la identificacion
            header += bytes([0x12,0x34])
            # Ponemos a 0 los flags y el puto offser ATENTO A ESTO OSTIA PUTA QUE VAS A TENER QUE CAMBIARLO, NO ME SEAS PUTO SUBNORMAL
            # Si solo hay un paquete todo a 0
            if numPackages == 1:
                header += b'\x00\x00' #Por defecto 0
            # Si no, se trata del ultimo paquete. Los flags a 0, pero hay un offset
            else: 
                offset = (i * maxPayloadLenght)//8
                print(offset.to_bytes(2, byteorder='big'))
                # los flags son 001
                header += offset.to_bytes(2, byteorder='big')
            # noveno byte en TTL. Por defecto es 64
            header += (64).to_bytes(1, byteorder='big')
            # Decimo byte el protocolo
            header += protocol.to_bytes(1, byteorder='big')
            # Calculamos el checksum y lo añadimos
            header += b'\x00\x00' #Por defecto 0
            # IPs origen y destino
            # TODO revisar el pack
            header +=  myIP.to_bytes(4, byteorder='big')
            header += dstIP.to_bytes(4, byteorder='big')
            # Si hay ipOpts lo añadimos
            if ipOpts is not None:
                header += ipOpts
            checksum = chksum(header)
            # print(struct.pack('!H',checksum))
            header[10:12] = struct.pack('!H',checksum)
        else:
            # Primer byte. version y la longitud total de la cabecera  
            header += ((0x40)+(ipHeaderLenght//4)).to_bytes(1, byteorder='big')
            # Segundo byte. Siempre 0
            header += (0).to_bytes(1, byteorder='big')
            # Su longitud será lo que no hemos enviado del data mas la longitud del header
            header += (maxPayloadLenght + ipHeaderLenght).to_bytes(2, byteorder='big')
            # Quinto y sexto la identificacion
            header += bytes([0x12,0x34])
            # if i == (numPackages):
            #    header += ((i * maxPayloadLenght) // 8).to_bytes(2, byteorder='big')
            # else:
            #    header += (32 + ((i * maxPayloadLenght) // 8)).to_bytes(2, byteorder='big')
            # Ponemos a 0 los flags y el puto offset ATENTO A ESTO OSTIA PUTA QUE VAS A TENER QUE CAMBIARLO, NO ME SEAS PUTO SUBNORMAL
            # El offset en este caso siempre va a ser esto
            offset = (i * maxPayloadLenght)//8
            # los flags son 001
            flags = b'\x20\x00'

            header += flags + offset.to_bytes(2, byteorder='big')
            # noveno byte en TTL. Por defecto es 64
            header += (64).to_bytes(1, byteorder='big')
            # Decimo byte el protocolo
            header += protocol.to_bytes(1, byteorder='big')
            # Calculamos el checksum y lo añadimos
            header += b'\x00\x00' #Por defecto 0
            # IPs origen y destino
            # TODO revisar el pack
            header +=  myIP.to_bytes(4, byteorder='big')
            header += dstIP.to_bytes(4, byteorder='big')
            
            # Si hay ipOpts lo añadimos
            if ipOpts is not None:
                header += ipOpts
            checksum = chksum(header)
            # print(struct.pack('!H',checksum))
            header[10:12] = struct.pack('!H',checksum)
        # Añadimos los datos del payload al datagrama final
        datagram = bytearray()
        datagram += header
        if numPackages == 1:
            print("yeah")
            datagram += data
        elif i == (numPackages):
            datagram += data[i * maxPayloadLenght :]
        else:
            datagram += data[i * maxPayloadLenght : (i+1) * maxPayloadLenght]
        
        # Calculamos la MAC de destino
        if (myIP & netmask) == (dstIP & netmask):
            dstMAC = ARPResolution(dstIP)
        else:
            dstMAC = ARPResolution(defaultGW)
            print("HERE WE ARE :)")
        # Enviamos el datagrama con sendEthernetFrame
        # print(datagram)
        sendEthernetFrame(datagram, len(datagram), bytes([0x08,0x00]),dstMAC)
        i += 1


    




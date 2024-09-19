import socket
import time
import string
from modules.diffie_hellman import getLargePrimeNumber, getPrimitiveRoot, keyGeneration, sharedKeyGeneration
from modules.des import DES_Algorithm

# Definindo o endereço e porta do servidor
serverPort = 8001
serverIP = "127.0.0.1"

# Função para gerar uma chave para o algoritmo DES a partir da chave compartilhada


def keyGenerationForDES(p, q, sharedKey):
    '''
    Esta função gera uma chave de comprimento suficiente para o algoritmo DES,
    utilizando a chave compartilhada formada e os parâmetros globais (p e q).
    '''
    # Mapeamento de caracteres ASCII para os valores da chave
    mapping = {}
    for index, letter in enumerate(string.ascii_letters):
        mapping[index] = letter

    # Multiplica os valores para formar uma string base para gerar a chave
    val = str(sharedKey * p * q)

    # Converte para uma chave de caracteres a partir do mapeamento
    finalKey = []
    for index in range(0, len(val), 2):
        finalKey.append(mapping[int(val[index:index + 1]) % len(mapping)])

    # Garante que a chave tenha pelo menos 8 caracteres
    while len(finalKey) < 8:
        finalKey += finalKey

    # Retorna a chave final com tamanho apropriado
    return "".join(finalKey[:8])


def main():
    # Criando o socket do servidor
    server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server.bind((serverIP, serverPort))
    server.listen(1)  # Máximo de 1 conexão aguardando

    # Estabelecendo a conexão com o cliente
    print("Aguardando conexão do cliente...")
    client_sock, address = server.accept()  # Aceita a conexão do cliente
    print(client_sock.recv(4096).decode())  # Exibe a mensagem de conexão

    # Definindo os parâmetros globais (p e q)
    p = getLargePrimeNumber(1000, 2000)  # Gerando um número primo grande
    q = getPrimitiveRoot(p, True)  # Raiz primitiva do número primo

    print("Enviando parâmetros globais para o cliente...\n")
    client_sock.send(str(p).encode())
    time.sleep(2)  # Pausa para garantir sincronização
    client_sock.send(str(q).encode())

    # Gerando o par de chaves pública-privada para o servidor
    privateServer, publicServer = keyGeneration(p, q)
    time.sleep(2)

    # Enviando a chave pública do servidor para o cliente
    client_sock.send(str(publicServer).encode())

    # Recebendo a chave pública do cliente
    publicClient = int(client_sock.recv(4096).decode())

    time.sleep(2)

    # Gerando a chave compartilhada e convertendo-a para chave do DES
    key = int(str(sharedKeyGeneration(publicClient, privateServer, p)), 16)
    DES_key = keyGenerationForDES(p, q, key)
    
    # Loop de recepção de mensagens
    while True:
        # Recebe mensagem criptografada
        actual_message = client_sock.recv(4096).decode()
        # Descriptografa a mensagem
        message = DES_Algorithm(text=actual_message,
                                key=DES_key, encrypt=False).DES()

        # Verifica se a mensagem não é vazia, o que encerraria a comunicação
        if message != "":
            # Exibe a mensagem criptografada
            print(f"Mensagem criptografada recebida transformada em hexadecimal: {actual_message.encode().hex()}")
            # Exibe a mensagem descriptografada
            print(f"Mensagem descriptografada: {message}\n")
        else:
            client_sock.close()  # Fecha a conexão ao receber a mensagem vazia
            break


if __name__ == '__main__':
    main()

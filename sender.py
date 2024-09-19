import socket
import time
import string
from modules.diffie_hellman import keyGeneration, sharedKeyGeneration
from modules.des import DES_Algorithm

# Definindo o endereço e porta do servidor ao qual vamos nos conectar
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
    # Criando o socket do cliente
    client = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

    # Estabelecendo a conexão com o servidor
    print("Estabelecendo conexão com o servidor...")
    client.connect((serverIP, serverPort))
    client.send("Conectado!".encode())  # Envia uma mensagem inicial
    print("Conectado!")

    # Recebendo os parâmetros globais p (número primo) e q (raiz primitiva)
    p = int(client.recv(4096).decode())
    q = int(client.recv(4096).decode())

    print(f"Número primo grande: {p}")
    print(f"Raiz primitiva: {q}\n")

    # Gerando o par de chaves pública-privada para o cliente
    privateClient, publicClient = keyGeneration(p, q)
    time.sleep(2)  # Pausa para garantir sincronização

    # Recebendo a chave pública do servidor
    publicServer = int(client.recv(4096).decode())

    # Enviando a chave pública do cliente para o servidor
    client.send(str(publicClient).encode())

    time.sleep(2)

    # Gerando a chave compartilhada e convertendo-a para chave do DES
    key = int(str(sharedKeyGeneration(publicServer, privateClient, p)), 16)
    DES_key = keyGenerationForDES(p, q, key)
    
    print("Quando quiser encerrar a comunicação, envie uma mensagem vazia!\n")

    # Loop de envio de mensagens
    while True:
        message_to_send = input("Digite sua mensagem: ")  # Entrada de mensagem do usuário
        print("\n")

        # Criptografando a mensagem com o DES
        encryptedMessage = DES_Algorithm(
            text=message_to_send, key=DES_key, encrypt=True).DES()
        # Envia a mensagem criptografada
        client.send(encryptedMessage.encode())

        if message_to_send == "":
            time.sleep(2)
            client.close()  # Fecha a conexão ao mandar mensagem vazia
            break


if __name__ == '__main__':
    main()

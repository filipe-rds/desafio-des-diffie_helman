import random  # Importa a biblioteca para geração de números aleatórios

'''
Parâmetros globais usados no Diffie-Hellman:
1. q = Número primo grande
2. a = Raiz primitiva de q

Lógica do protocolo Diffie-Hellman:
1. A chave privada é um número aleatório (chamado x).
2. A chave pública é gerada pela fórmula: (a^x) mod q
3. A chave compartilhada entre duas partes é: (Chave Pública de B) ^ (Chave Privada de A) mod q
'''


def getLargePrimeNumber(lowerLimit, upperLimit):
    '''
    Função utilitária para gerar um número primo grande dentro de um intervalo.
    
    Entrada:
    - lowerLimit: Limite inferior do intervalo
    - upperLimit: Limite superior do intervalo

    Saída:
    - Um número primo escolhido aleatoriamente dentro do intervalo dado
    '''
    p = 2
    # Certifica-se de que o limite superior seja no mínimo 2 (pois 2 é o menor primo)
    upperLimit = max(upperLimit, 2)
    # Cria uma lista para verificar a primalidade dos números usando o crivo de Eratóstenes
    isPrime = [False] * 2 + [True] * (upperLimit - 1)
    # Verifica a primalidade de todos os números até o limite superior
    while (p ** 2 < upperLimit):
        if isPrime[p]:
            # Marca os múltiplos de p como não primos
            for i in range(p ** 2, upperLimit + 1, p):
                isPrime[i] = False
        p += 1

    # Retorna um número primo aleatório dentro dos limites
    result = [i for i, check in enumerate(isPrime) if check and i > lowerLimit]
    return random.choice(result)  # Escolhe um número primo aleatório da lista


def getPrimitiveRoot(q, reverse=False):
    '''
    Função que encontra uma raiz primitiva de um número primo q.
    A raiz primitiva de um número primo gera todos os restos possíveis
    quando suas potências são calculadas módulo q.

    Exemplo:
    Para q = 7, uma raiz primitiva pode ser o número 3.
    Potências de 3 modulo 7 geram todos os restos: 1, 2, 3, ..., 6.
    
    Entrada:
    - q: O número primo para o qual queremos encontrar a raiz primitiva.
    - reverse: Se verdadeiro, a busca começa em ordem decrescente.

    Saída:
    - A raiz primitiva de q, ou None se q não for primo.
    '''
    if isPrime(q):  # Verifica se q é primo
        test = set()  # Armazena os restos gerados
        # Gera uma lista de possíveis raízes primitivas
        pos = [x for x in range(2, q)]
        if reverse:
            # Inverte a lista se a busca for em ordem decrescente
            pos = pos[::-1]

        for num in pos:
            for i in range(1, q):
                val = (num ** i) % q  # Calcula a potência de num modulo q
                if val in test:  # Se o valor já foi gerado, não é uma raiz primitiva
                    test = set()  # Reinicia o teste para o próximo número
                    break
                else:
                    test.add(val)  # Adiciona o valor gerado ao conjunto

                if len(test) == q - 1:  # Se todos os restos forem gerados, num é uma raiz primitiva
                    return num
    else:
        print("O número inserido não é primo: Não há raiz primitiva")
        return None


def keyGeneration(number, root, privateKeyLimit=101):
    '''
    Gera a chave privada e a chave pública com base nos parâmetros globais.
    
    Entrada:
    - number: O número primo grande (q)
    - root: A raiz primitiva de q
    - privateKeyLimit: Limite superior opcional para o valor da chave privada

    Saída:
    - Chave privada (número aleatório dentro do limite)
    - Chave pública, calculada como (root ^ privateKey) % number
    '''
    privateKeyLimit = max(
        privateKeyLimit, 101)  # Define o limite mínimo para a chave privada
    # Gera a chave privada aleatoriamente
    private = random.randint(privateKeyLimit - 100, privateKeyLimit)
    public = (root ** private) % number  # Calcula a chave pública
    return (private, public)  # Retorna as chaves privada e pública


def sharedKeyGeneration(publicKey, privateKey, number):
    '''
    Calcula a chave compartilhada entre duas partes no Diffie-Hellman.
    
    Entrada:
    - publicKey: A chave pública da outra parte
    - privateKey: A chave privada da parte atual
    - number: O número primo grande (q)

    Saída:
    - A chave compartilhada calculada como (publicKey ^ privateKey) % number
    '''
    return (publicKey ** privateKey) % number


def isPrime(number):
    '''
    Verifica se um número é primo. A segurança do Diffie-Hellman
    depende da escolha de um número primo grande.
    
    Entrada:
    - number: O número a ser verificado

    Saída:
    - True se o número for primo, False caso contrário
    '''
    for i in range(2, int(number ** 0.5) + 1):  # Itera até a raiz quadrada de 'number'
        if number % i == 0:  # Se o número for divisível por i, não é primo
            return False
    return True  # Retorna True se não houver divisores


if __name__ == '__main__':
    # Parâmetros globais do Diffie-Hellman
    # Número de bits do primo grande (usaremos um primo pequeno para teste)
    prime_length = 16
    q = getLargePrimeNumber(1000, 5000)  # Gera um número primo grande
    print(f"Número primo gerado (q): {q}")

    a = getPrimitiveRoot(q)  # Gera uma raiz primitiva de q
    print(f"Raiz primitiva de q (a): {a}")

    # Parte A (Emissor)
    # Gera a chave privada e pública de A
    a_private, a_public = keyGeneration(q, a)
    print(f"Chave privada de A: {a_private}")
    print(f"Chave pública de A: {a_public}")

    # Parte B (Receptor)
    # Gera a chave privada e pública de B
    b_private, b_public = keyGeneration(q, a)
    print(f"Chave privada de B: {b_private}")
    print(f"Chave pública de B: {b_public}")

    # Cálculo da chave compartilhada
    a_shared_key = sharedKeyGeneration(
        b_public, a_private, q)  # Chave compartilhada por A
    b_shared_key = sharedKeyGeneration(
        a_public, b_private, q)  # Chave compartilhada por B

    print(f"Chave compartilhada calculada por A: {a_shared_key}")
    print(f"Chave compartilhada calculada por B: {b_shared_key}")

    # Verifica se ambas as chaves compartilhadas são iguais
    assert a_shared_key == b_shared_key, "Erro: As chaves compartilhadas não correspondem!"
    print("Chaves compartilhadas coincidem! A troca de chaves foi bem-sucedida.")

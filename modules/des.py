'''
Implementando o algoritmo DES

Considerando a Chave:
    1. A chave precisa ter exatamente 8 bytes,
    2. Um "parity drop" (remoção de bits de paridade) é feito para convertê-la em uma chave de 56 bits,
    3. São necessárias 16 subchaves, uma para cada rodada,
    4. Em cada rodada, a chave é dividida em duas metades, uma rotação circular à esquerda é realizada e depois comprimida para 48 bits,
    5. O deslocamento é feito por 1 bit nas rodadas 1, 2, 9 e 16, e por 2 bits nas outras rodadas.
'''


class DES_Algorithm():

    def __init__(self, text, key, encrypt=True):
        '''
        Inicializa o algoritmo DES com o texto e a chave. O parâmetro "encrypt" indica
        se é para criptografar ou descriptografar.
        '''
        self.text = text
        self.key = key
        self.encrypt = encrypt
        self.roundKeys = []  # Armazena as subchaves geradas para cada rodada

    def string_to_bit_array(self, text):
        '''
        Converte uma string em um array de bits. Note que os bits "0" mais significativos (MSB) são 
        omitidos por padrão e precisam ser adicionados.
        Pressupõe-se que os caracteres têm 8 bits, seguindo a representação ASCII.
        
        Entrada: Uma string de caracteres
        Saída: Uma string de 0s e 1s (bits)
        '''
        result = []
        for letter in text:
            d = format(ord(letter), 'b')  # Converte o caractere em binário
            # Preenche os bits à esquerda com 0s para garantir 8 bits
            d = "0" * (8 - len(d)) + d
            result.append(d)
        return "".join(result)

    def bit_array_to_string(self, array):
        '''
        Recria a string a partir do array de bits. Pressupõe-se que os caracteres
        têm 8 bits, seguindo a representação ASCII.
        '''
        result = []
        for i in range(0, len(array), 8):
            # Converte o bloco de 8 bits em um caractere
            result.append(chr(int(array[i:i + 8], 2)))
        return "".join(result)

    def permut(self, key, table):
        '''
        Aplica uma permutação ao valor da chave (ou bloco de bits) usando a tabela fornecida.

        1. Compacta e embaralha a chave de entrada de 64 bits para 56 bits.
        2. Compacta e embaralha a chave deslocada de 56 bits para 48 bits.
        3. Expande o lado direito do texto de 32 bits para 48 bits.
        
        Entrada: Chave como uma string de 0s e 1s, e uma tabela como lista de índices
        Saída: String permutada de 0s e 1s
        '''
        result = [0] * len(table)
        for index_in_result, index_in_key in enumerate(table):
            result[index_in_result] = key[index_in_key]

        return "".join(result)

    def xor(self, text, key):
        '''
        Aplica a operação XOR entre o texto expandido e a subchave da rodada.

        Entrada: Texto e chave, ambos como strings de 0s e 1s
        Saída: Resultado da operação XOR como uma string de 0s e 1s
        '''
        result = []
        for i, j in zip(text, key):
            if i == j:
                result.append("0")
            else:
                result.append("1")

        return "".join(result)

    def int_to_binary(self, number):
        '''
        Converte um número inteiro em uma string de 4 bits.
        '''
        string = str(bin(number).replace("0b", ""))
        return "0" * (4 - len(string)) + string

    def subsitution(self, key, table):
        '''
        Realiza a substituição do bloco de bits usando as caixas S (S-boxes).
        Cada caixa S reduz o bloco de 6 bits para 4 bits.
        
        1. Divide a chave em blocos de 6 bits.
        2. Usa a primeira e última posição como número da linha e as quatro posições do meio como número da coluna.
        3. Aplica a substituição e retorna um bloco compactado de 4 bits.
        '''
        blocks = []
        for i in range(0, len(key), 6):
            blocks.append(key[i:i + 6])

        result = []
        for index, block in enumerate(blocks):
            # Determina a linha
            rowNumber = int(str(block[0]) + str(block[5]), 2)
            # Determina a coluna
            columnNumber = "".join(list(map(lambda x: str(x), block[1:5])))
            columnNumber = int(columnNumber, 2)
            result.append(self.int_to_binary(
                table[index][rowNumber][columnNumber]))  # Aplica a caixa S

        return "".join(result)

    def keyGeneration(self):
        '''
        Gera 16 subchaves para as rodadas de criptografia/descriptografia a partir da chave principal.

        1. A chave é truncada para 8 bytes.
        2. Um "parity drop" é feito para obter uma chave de 56 bits.
        3. Em cada rodada, uma rotação circular à esquerda é feita em ambas as metades da chave.
        4. A chave é comprimida para 48 bits e usada na rodada.
        '''
        # Verifica o comprimento da chave
        if len(self.key) < 8:
            print("A chave deve ter pelo menos 8 bytes/caracteres")
            exit(0)
        else:
            self.key = self.key[:8]

        # Define os deslocamentos (shifts) para cada rodada
        shift_count = [1, 1, 2, 2, 2, 2, 2, 2, 1, 2, 2, 2, 2, 2, 2, 1]

        # Converte a chave em binário
        key = self.string_to_bit_array(self.key)

        # Aplica o "parity drop" para compactar a chave para 56 bits
        key = self.permut(key, keyCompression64_56)

        # Divide a chave em duas metades
        keyLeft = key[:28]
        keyRight = key[28:]
        for count in shift_count:
            # Aplica a rotação circular à esquerda
            keyLeft = keyLeft[count:] + keyLeft[:count]
            keyRight = keyRight[count:] + keyRight[:count]
            # Compacta para 48 bits e armazena a subchave
            self.roundKeys.append(self.permut(keyLeft + keyRight,
                                              keyCompression56_48))

    def DES(self):
        '''
        Implementa o algoritmo DES principal.

        1. Gera as subchaves de cada rodada (se ainda não foram geradas).
        2. Converte o texto para binário.
        3. Aplica a permutação inicial.
        4. Divide o texto em duas metades.
        5. Expande a metade direita para 48 bits.
        6. Aplica XOR entre a metade direita e a subchave da rodada.
        7. Realiza substituição com as caixas S e permutação.
        8. Aplica XOR na metade esquerda com o resultado da função Feistel.
        9. Troca as metades para a próxima rodada.
        10. Após 16 rodadas, aplica a permutação final.
        11. Converte o resultado de volta para texto.

        O algoritmo é executado para cada bloco de 64 bits do texto. Caso o texto
        não tenha um múltiplo de 8 bytes, são adicionados espaços em branco como padding.
        '''
        if len(self.roundKeys) == 0:
            self.keyGeneration()

        # Decide a ordem das chaves: normal para criptografia, invertida para descriptografia
        if self.encrypt:
            keys = self.roundKeys
        else:
            keys = self.roundKeys[::-1]

        text = self.text
        
        # Adiciona padding ao texto se o comprimento não for múltiplo de 8
        if len(text) % 8 != 0:
            text += " " * (8 - (len(text) % 8))

        result = []
        for i in range(0, len(text), 8):
            # Pega o bloco de 8 caracteres (64 bits)
            block = text[i:i + 8]
            # Converte o bloco para binário
            block = self.string_to_bit_array(block)
            # Aplica a permutação inicial
            block = self.permut(block, initialPermutation)

            for roundNumber in range(16):  # Executa 16 rodadas
                # Divide o bloco em duas metades
                blockLeft = block[:32]
                blockRight = block[32:]

                # Expande a metade direita de 32 para 48 bits
                expandedRight = self.permut(
                    blockRight, textExpansion32_48)

                # Aplica XOR com a subchave da rodada
                key = self.xor(expandedRight, keys[roundNumber])

                # Aplica a substituição com as caixas S e permutação
                key = self.subsitution(key, subsitutionBox)
                key = self.permut(key, keyShuffle)

                # Aplica XOR na metade esquerda com o resultado da função Feistel
                blockLeft = self.xor(blockLeft, key)

                # Troca as metades para a próxima rodada
                blockLeft, blockRight = blockRight, blockLeft
                block = blockLeft + blockRight

            # Aplica a permutação final
            block = self.permut(block[32:] + block[:32],
                                finalPermutation)

            # Adiciona o bloco criptografado ao resultado final
            result.append(self.bit_array_to_string(block))
        
        # Concatena os blocos criptografados/decifrados em uma única string
        result_final = "".join(result)

        return result_final


# =====================================================================
#                       SEÇÃO DE TABELAS DO DES
# =====================================================================
# Esta seção contém todas as tabelas necessárias para o algoritmo DES.

keyCompression64_56 = [56, 48, 40, 32, 24, 16, 8,
                       0, 57, 49, 41, 33, 25, 17,
                       9, 1, 58, 50, 42, 34, 26,
                       18, 10, 2, 59, 51, 43, 35,
                       62, 54, 46, 38, 30, 22, 14,
                       6, 61, 53, 45, 37, 29, 21,
                       13, 5, 60, 52, 44, 36, 28,
                       20, 12, 4, 27, 19, 11, 3]
'''
Esta tabela é usada para permutar a chave de entrada
e compactá-la de 64 bits para 56 bits, removendo os bits de paridade.
'''


keyCompression56_48 = [13, 16, 10, 23, 0, 4, 2, 27,
                       14, 5, 20, 9, 22, 18, 11, 3,
                       25, 7, 15, 6, 26, 19, 12, 1,
                       40, 51, 30, 36, 46, 54, 29, 39,
                       50, 44, 32, 47, 43, 48, 38, 55,
                       33, 52, 45, 41, 49, 35, 28, 31]
'''
Esta tabela é usada para permutar a chave deslocada
e compactá-la de 56 bits para 48 bits.
Ela é usada após a chave ser rotacionada (shift) para a esquerda.
'''


initialPermutation = [57, 49, 41, 33, 25, 17, 9, 1,
                      59, 51, 43, 35, 27, 19, 11, 3,
                      61, 53, 45, 37, 29, 21, 13, 5,
                      63, 55, 47, 39, 31, 23, 15, 7,
                      56, 48, 40, 32, 24, 16, 8, 0,
                      58, 50, 42, 34, 26, 18, 10, 2,
                      60, 52, 44, 36, 28, 20, 12, 4,
                      62, 54, 46, 38, 30, 22, 14, 6]
'''
Esta tabela é usada para reorganizar os bits
do texto de entrada de 64 bits antes de iniciar o processo de criptografia.
A permutação embaralha os bits de forma não linear para aumentar a segurança.
'''


textExpansion32_48 = [31, 0, 1, 2, 3, 4,
                      3, 4, 5, 6, 7, 8,
                      7, 8, 9, 10, 11, 12,
                      11, 12, 13, 14, 15, 16,
                      15, 16, 17, 18, 19, 20,
                      19, 20, 21, 22, 23, 24,
                      23, 24, 25, 26, 27, 28,
                      27, 28, 29, 30, 31, 0]
'''
Esta tabela é usada para expandir a metade direita do texto,
de 32 bits para 48 bits, para que possa ser utilizada na operação XOR
com a subchave gerada para cada rodada do DES.
A expansão introduz repetição de bits para aumentar a difusão da chave.
'''


subsitutionBox = [
    # Caixa S1
    [[14, 4, 13, 1, 2, 15, 11, 8, 3, 10, 6, 12, 5, 9, 0, 7],
     [0, 15, 7, 4, 14, 2, 13, 1, 10, 6, 12, 11, 9, 5, 3, 8],
     [4, 1, 14, 8, 13, 6, 2, 11, 15, 12, 9, 7, 3, 10, 5, 0],
     [15, 12, 8, 2, 4, 9, 1, 7, 5, 11, 3, 14, 10, 0, 6, 13]],

    # Caixa S2
    [[15, 1, 8, 14, 6, 11, 3, 4, 9, 7, 2, 13, 12, 0, 5, 10],
     [3, 13, 4, 7, 15, 2, 8, 14, 12, 0, 1, 10, 6, 9, 11, 5],
     [0, 14, 7, 11, 10, 4, 13, 1, 5, 8, 12, 6, 9, 3, 2, 15],
     [13, 8, 10, 1, 3, 15, 4, 2, 11, 6, 7, 12, 0, 5, 14, 9]],

    # Caixa S3
    [[10, 0, 9, 14, 6, 3, 15, 5, 1, 13, 12, 7, 11, 4, 2, 8],
     [13, 7, 0, 9, 3, 4, 6, 10, 2, 8, 5, 14, 12, 11, 15, 1],
     [13, 6, 4, 9, 8, 15, 3, 0, 11, 1, 2, 12, 5, 10, 14, 7],
     [1, 10, 13, 0, 6, 9, 8, 7, 4, 15, 14, 3, 11, 5, 2, 12]],

    # Caixa S4
    [[7, 13, 14, 3, 0, 6, 9, 10, 1, 2, 8, 5, 11, 12, 4, 15],
     [13, 8, 11, 5, 6, 15, 0, 3, 4, 7, 2, 12, 1, 10, 14, 9],
     [10, 6, 9, 0, 12, 11, 7, 13, 15, 1, 3, 14, 5, 2, 8, 4],
     [3, 15, 0, 6, 10, 1, 13, 8, 9, 4, 5, 11, 12, 7, 2, 14]],

    # Caixa S5
    [[2, 12, 4, 1, 7, 10, 11, 6, 8, 5, 3, 15, 13, 0, 14, 9],
     [14, 11, 2, 12, 4, 7, 13, 1, 5, 0, 15, 10, 3, 9, 8, 6],
     [4, 2, 1, 11, 10, 13, 7, 8, 15, 9, 12, 5, 6, 3, 0, 14],
     [11, 8, 12, 7, 1, 14, 2, 13, 6, 15, 0, 9, 10, 4, 5, 3]],

    # Caixa S6
    [[12, 1, 10, 15, 9, 2, 6, 8, 0, 13, 3, 4, 14, 7, 5, 11],
     [10, 15, 4, 2, 7, 12, 9, 5, 6, 1, 13, 14, 0, 11, 3, 8],
     [9, 14, 15, 5, 2, 8, 12, 3, 7, 0, 4, 10, 1, 13, 11, 6],
     [4, 3, 2, 12, 9, 5, 15, 10, 11, 14, 1, 7, 6, 0, 8, 13]],

    # Caixa S7
    [[4, 11, 2, 14, 15, 0, 8, 13, 3, 12, 9, 7, 5, 10, 6, 1],
     [13, 0, 11, 7, 4, 9, 1, 10, 14, 3, 5, 12, 2, 15, 8, 6],
     [1, 4, 11, 13, 12, 3, 7, 14, 10, 15, 6, 8, 0, 5, 9, 2],
     [6, 11, 13, 8, 1, 4, 10, 7, 9, 5, 0, 15, 14, 2, 3, 12]],

    # Caixa S8
    [[13, 2, 8, 4, 6, 15, 11, 1, 10, 9, 3, 14, 5, 0, 12, 7],
     [1, 15, 13, 8, 10, 3, 7, 4, 12, 5, 6, 11, 0, 14, 9, 2],
     [7, 11, 4, 1, 9, 12, 14, 2, 0, 6, 10, 13, 15, 3, 5, 8],
     [2, 1, 14, 7, 4, 10, 8, 13, 15, 12, 9, 0, 3, 5, 6, 11]]
]
'''
Estas caixas de substituição (caixas S ou S-boxes) são uma parte fundamental do algoritmo DES.
Cada caixa S recebe uma entrada de 6 bits e a transforma em uma saída de 4 bits.
As caixas S realizam substituições não lineares, o que aumenta a confusão no processo de criptografia.
No total, existem 8 caixas S, e cada uma delas contém uma matriz de 4x16, representando 64 valores possíveis.
'''


keyShuffle = [15, 6, 19, 20, 28, 11, 27, 16,
              0, 14, 22, 25, 4, 17, 30, 9,
              1, 7, 23, 13, 31, 26, 2, 8,
              18, 12, 29, 5, 21, 10, 3, 24]
'''
Esta tabela é usada após a substituição pela caixa S
para embaralhar os bits antes de fazer o XOR com a metade esquerda do texto.
Isso aumenta a difusão dos bits, garantindo que pequenas mudanças no texto
de entrada ou na chave resultem em uma saída completamente diferente.
'''


finalPermutation = [39, 7, 47, 15, 55, 23, 63, 31,
                    38, 6, 46, 14, 54, 22, 62, 30,
                    37, 5, 45, 13, 53, 21, 61, 29,
                    36, 4, 44, 12, 52, 20, 60, 28,
                    35, 3, 43, 11, 51, 19, 59, 27,
                    34, 2, 42, 10, 50, 18, 58, 26,
                    33, 1, 41, 9, 49, 17, 57, 25,
                    32, 0, 40, 8, 48, 16, 56, 24]
'''
Esta tabela é aplicada ao final das 16 rodadas de criptografia.
Ela reordena os bits do texto de saída para gerar o texto cifrado final.
A permutação final é a inversa da permutação inicial, retornando os bits
para uma ordem "embaralhada", mas consistente com o processo de permutação.
'''


if __name__ == '__main__':
    d = DES_Algorithm("Des_Algorithm", "key_master")
    encryptedText = d.DES()
    c = DES_Algorithm(encryptedText, "key_master", False)
    decryptedText = c.DES()

    print(f"Mensagem criptografada em hexadecimal:{encryptedText.encode().hex()}")
    print(f"Mensagem descriptografada: {decryptedText.strip(" ")}")
    


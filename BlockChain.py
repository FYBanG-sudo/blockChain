import hashlib
import time
import ecdsa


# sha256函数
def sha256(value):
    return hashlib.sha256(value.encode('utf-8')).hexdigest()


# 生成密钥对，需要'name'参数
class genKeyPair:
    def __init__(self, name):
        self.name = name
        self.privateKey = ecdsa.SigningKey.generate(curve=ecdsa.SECP256k1)
        self.publicKey = self.privateKey.get_verifying_key()


# 交易
class Transaction:
    def __init__(self, transfer, payee, amount):
        # 转账人
        self.transfer = transfer
        # 收款人
        self.payee = payee
        # 交易金额
        self.amount = amount

    # 返回交易信息
    def getTransactionMessage(self):
        if self.transfer == 'SYSTEM':
            return {
                'transfer': 'SYSTEM',
                'payee': self.payee.name,
                'amount': self.amount
            }
        elif self.transfer == '创世':
            return self.__dict__
        else:
            return {
                'transfer': self.transfer.name,
                'payee': self.payee.name,
                'amount': self.amount
            }

    # 返回交易信息的hash
    def getHashMessage(self):
        data = str(self.transfer) + str(self.payee) + str(self.amount)
        return str(sha256(data)).encode()

    # 用转账人的私钥进行数字签名
    def sign(self):
        self.signature = self.transfer.privateKey.sign(self.getHashMessage())

    # 验证数字签名
    def isValid(self, vk):
        # 如果是矿工奖励直接返回True
        if self.transfer == 'SYSTEM':
            return True
        try:
            vk.verify(self.signature, self.getHashMessage())
        except ecdsa.keys.BadSignatureError:
            return False
        return True


class Block:
    def __init__(self, transactions, previousHash=''):
        # 块的所有交易信息
        self.transactions = transactions
        # 上一个区块的hash
        self.previousHash = previousHash
        # 时间戳
        self.timestamp = time.time()
        # nonce值
        self.nonce = 0
        # 块的hash
        self.hash = self.getHash()

    # 返回块hash值
    def getHash(self):
        data = str(self.transactions) + self.previousHash + str(self.timestamp) + str(self.nonce)
        return sha256(data)

    # 挖矿
    def mine(self, difficulty):
        # 先验证 transaction pool 里面的每一条交易是否被篡改
        self.validateBlockTransactions()
        # 挖矿
        self.nonce = 0
        self.hash = self.getHash()
        ans = '0' * difficulty
        while self.hash[0:difficulty] != ans:
            self.nonce += 1
            self.hash = self.getHash()
        print("挖矿成功", self.hash)

    # 验证 transaction pool里的数字签名
    def validateBlockTransactions(self):
        for i in self.transactions:
            if i.transfer == 'SYSTEM':
                continue
            if not i.isValid(i.transfer.publicKey):
                raise Warning("invalib transaction fount in transactions, 发现异常交易")

    # 返回块信息，方便打印
    def getBlockMessage(self):
        transactionMessage = [i.getTransactionMessage() for i in self.transactions]
        blockMessage = {'transactions': transactionMessage,
                        'previousHash': self.previousHash,
                        'timestamp': self.timestamp,
                        'nonce': self.nonce,
                        'hash': self.hash
                        }
        return blockMessage


# Chain 类实现
class Chain:
    def __init__(self):
        # 链信息，初始只有祖先区块，包含每一个块信息，挖矿成功就加入到这里
        self.message = [self.genesisBlock()]
        # 交易池
        self.transactionPool = []
        # 矿工奖励
        self.minerReward = 50
        # 挖矿难度
        self.difficulty = 4

    # 祖先区块
    def genesisBlock(self):
        newTransaction = Transaction("创世", "创世", "创世")
        block = Block([newTransaction], '')
        return block

    # 添加区块到链
    def addBlockToChain(self, newBlock):
        newBlock.previousHash = self.message[-1].hash
        newBlock.mine(self.difficulty)
        self.message.append(newBlock)

    # 添加交易到交易池
    def addTransactionPool(self, transaction):
        # 添加前先验证交易是否被篡改
        if transaction.transfer == 'SYSTEM' or transaction.isValid(transaction.transfer.publicKey):
            print('valib transaction')
            self.transactionPool.append(transaction)
        else:
            raise Warning("invalib transaction")

    # 挖矿如果成功就把块加入到链上
    def mineTransactionPool(self, minerRewardAddress):
        # 发放矿工奖励，并且把这笔交易加到交易池里
        minerRewardTransaction = Transaction('SYSTEM', minerRewardAddress, self.minerReward)
        self.addTransactionPool(minerRewardTransaction)
        # 挖矿
        newBlock = Block(self.transactionPool, self.message[-1].hash)
        self.addBlockToChain(newBlock)
        self.transactionPool = []

    # 返回链信息，方便打印
    def getChainMessage(self):
        chainMessage = [i.getBlockMessage() for i in self.message]
        return chainMessage

    # 返回交易池信息，方便打印
    def getTransactionPoolMessage(self):
        message = [i.getTransactionMessage() for i in self.transactionPool]
        return message

    # 验证链内内容是否被篡改
    def validateChain(self):
        # 只有一个祖先区块时
        if len(self.message) == 1:
            if self.message[0].getHash() != self.message[0].hash:
                return False
            return True
        for i in range(1, len(self.message)):
            # 先验证数字签名是否被篡改
            self.message[i].validateBlockTransactions()
            # 验证交易内容
            if self.message[i].getHash() != self.message[i].hash:
                print("数据篡改！！！")
                return False
            if self.message[i].previousHash != self.message[i - 1].hash:
                print("前后区块断裂！！！")
                return False
        return True


Coin = Chain()
sender = genKeyPair('Sender')
privateKeySender = sender.privateKey
publicKeySender = sender.publicKey
# print(privateKeySender.to_string().hex()) #私钥转换成十六进制字符串
# print(publicKeySender.to_string().hex())  #公钥转换成十六进制字符串

receiver = genKeyPair('Receiver')
privateKeyReceived = receiver.privateKey
publicKeyReceived = receiver.publicKey
# print(privateKeyReceived.to_string().hex())
# print(publicKeyReceived.to_string().hex())

t1 = Transaction(sender, receiver, 20)
t1.sign()  # 数字签名
print(t1.isValid(publicKeySender))
t2 = Transaction(receiver, sender, 10)
t2.sign()  # 数字签名
Coin.addTransactionPool(t1)
Coin.addTransactionPool(t2)
Coin.mineTransactionPool(receiver)
print(Coin.validateChain())
print(Coin.getChainMessage())

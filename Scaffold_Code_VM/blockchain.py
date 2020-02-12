import block

class Blockchain:
    def __init__(self, block_capacity):
        self.unconfirmed_transactions = []
        self.chain = []
        self.block_capacity = block_capacity
        #self.nodes = set()

    @property
    def last_block(self):
        return self.chain[-1]

    # def add_block(self, block):
    #     self.chain.extend([block])

    # def add_block(self, block, proof):
    #     """
    #     A function that adds the block to the chain after verification.
    #     """
    #     previous_hash = self.last_block.current_hash
    #
    #     if previous_hash != block.previous_hash:
    #         return False
    #
    #     if not self.is_valid_proof(block, proof):
    #         return False
    #
    #     block.current_hash = proof
    #     self.chain.append(block)
    #     return True

    def add_block(self, block):
        """
        A function that adds the block to the chain.
        """
        self.chain.append(block)

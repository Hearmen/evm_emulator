class  Storage(dict):
    """docstring for  Memory"""
    def __init__(self):
        super()
        
    def sstore(self, p, v):
        self[p] = v

    def sload(self, p):
        if not self.get(p):
            self[p] = 0
        v = self[p]
        return v

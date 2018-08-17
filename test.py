class AllOne:

    def __init__(self):
        """
        Initialize your data structure here.
        """
        self.keys = dict()
        self.counts = []

    def inc(self, key):
        """
        Inserts a new key <Key> with value 1. Or increments an existing key by 1.
        :type key: str
        :rtype: void
        """
        if key in self.keys:
            count = self.keys[key]
            if self.keys[key][0]+1 > self.counts[-1][0]:
                self.counts.append([self.keys[key][0]+1, {key}])
            count[1].remove(key)
        else:
            self.keys[key] = self.counts[0]
            self.counts[0][1].add(key)
            if len(self.counts) == 0:
                self.counts.append([1, {key}])

    def dec(self, key):
        """
        Decrements an existing key by 1. If Key's value is 1, remove it from the data structure.
        :type key: str
        :rtype: void
        """
        if key in self.counts[0][1]:
            self.counts[0][1].remove(key)
        else:
            pair = self.keys[key]
            pair


    def getMaxKey(self):
        """
        Returns one of the keys with maximal value.
        :rtype: str
        """
        if len(self.max_stack) == 0:
            return ""
        return self.max_stack[-1]

    def getMinKey(self):
        """
        Returns one of the keys with Minimal value.
        :rtype: str
        """
        if len(self.min_stack) == 0:
            return ""
        return self.min_stack[-1]

    def display(self):
        print(self.max_stack)
        print(self.min_stack)
        print(self.keys)
# Your AllOne object will be instantiated and called as such:
# obj = AllOne()
# obj.inc(key)
# obj.dec(key)
# param_3 = obj.getMaxKey()
# param_4 = obj.getMinKey()
if __name__ == '__main__':
    o = AllOne()
    o.inc('ss')
    o.inc('ss')
    o.inc('07')
    o.inc('07')
    o.inc('07')
    o.inc('sb')
    o.inc('sb')
    o.display()
    print(o.getMaxKey())
    print(o.getMinKey())
    o.inc('ss')
    o.dec('07')
    o.display()
    print(o.getMaxKey())
    print(o.getMinKey())
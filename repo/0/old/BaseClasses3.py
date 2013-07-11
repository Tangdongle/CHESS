#!/usr/env/bin Python

import game
import random
import sys

################################################################################
#                             Items                                            #
################################################################################
class Weapon(Item):
    norm = lambda x,y: x / math.sqrt(x**2 + y**2)
    def __init__(self, name, description='A weapon.', weight=0.0, special=''):
        super(Weapon,self).__init__(name)
        self.weight = weight
        self.desc = desc
        for i,d in zip(damage, self.damages):
            self.damages[d] = damage[i]

    def __str__(self):
        return self.desc

    def use(self, target, power):
        print "You attack with %s" % (self.name)
        try:
            strike = self.weight * math.sqrt(power) #Damage Calculation
            penalty = 1.0 if self.norm(power, self.weight) > 0.50 else 0.9
            #Normalized value to determine if str is equivalent (roughly 60% of
            #weight
            target.take_damage(strike ** penalty)
        except AttributeError:
            print "The weapon had no effect!"

class Armour(Item):
    def __init__(self, name, resistance=[0,0,0,0], special=''):
        super(Armour,self).__init__(name)
        #Resistances subject to change
        self.resistances = {'Physical':None, 'Ice':None,\
                                'Fire':None, 'Thunder':None}
        for i,r in zip(resistance, self.resistances):
            self.resistances[r] = resistance[i]

    def take_damage(self, damage):
        dmg_done = []
        for i,j in zip(hit, self.resistances):
            if (i-j) <= 0:
                dmg_done.append(0)
            else:
                dmg_done.append(i-j)
        return dmg_done


################################################################################
#                               Some Custom Jazz                               #
################################################################################



################################################################################
#                              Characters                                      #
################################################################################

class Player(Character):
    def __init__(self, name, hitpoints, gear, stats=self.__blankstats):
        super(Player, self).__init__(name, 100)
        self.stats = stats

    def set_stats(self):
        random.seed()
        for i in self.stats:
            self.stats[i] = random.randint(1,10)
            print "You were born with %d %s." % (self.stats[i], i)

    def take_damage(self, hit):
        for g in self.gear:
            hit -= g.take_damage(hit)
        hitpoints -= hit
        if hitpoints <= 0:
            self.die()

    def attack(self, target):
        try:
            self.mainhand.use(target)
        except AttributeError:
            print "You don't have a weapon equipped in your main hand!"
        try:
            self.offhand.use(target)
        except AttributeError:
            print "You don't have a weapon equipped in your off hand!"

    def die(self):
        super(Player, self).die()
        print "You have died! The curtains close for you..."
        sys.exit(0)


class Monster(Character):








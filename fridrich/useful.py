"""
module: useful
defines generally useful functions / methods for
all kinds of things
(Server & Client)

Author: Nilusink
"""
import typing
import types
import copy
import time


class List:
    """
    list functions
    """
    @staticmethod
    def remove_all(lst: list, value) -> list:
        """
        remove all values from list
        """
        return list(filter(lambda a: a != value, lst))

    @staticmethod
    def from_matrix(lst: list, index: int) -> types.GeneratorType:
        """
        make list from matrix (just return all elements of the matrix (2D))
        """
        for element in lst:
            yield element[index]

    @staticmethod
    def all_from_matrix(lst: list) -> types.GeneratorType:
        """
        yield all elements of all lists in parent list
        
        works with lists and tuples ONLY - no dicts
        """
        tmp = str(lst).strip().replace('[', '').replace(']', '').replace('(', '').replace(')', '')
        print(tmp)
        while ',,' in tmp:
            tmp = tmp.replace(',,', ',')
        lst = tmp.split(',')
        for element in lst:
            yield eval(element)

    @staticmethod
    def closest(number: float, lst: list) -> float:
        """
        check which element in list is closest to given number
        """
        cl = 0
        for element in lst:
            if abs(element-number) < abs(cl-number):
                cl = element
        return cl

    @staticmethod
    def singles(lst: list) -> list:
        """
        removes all clones from list
        
        also sorts it
        """
        return list(set(lst))

    @staticmethod
    def get_inner_dict_values(lst: list | dict, index) -> list:
        """
        when given ([{'a':5}, {'b':3}, {'a':2, 'b':3}], 'a') returns (5, 2)
        """
        out = list()
        for element in lst:
            if index in element:
                out.append(element[index])
        return out


class Dict:
    """
    dictionary functions
    """
    @staticmethod
    def indexes(dictionary: dict) -> list:
        """
        returns the indexes of the dictionary
        """
        return list(dictionary)

    @staticmethod
    def values(dictionary: dict) -> types.GeneratorType:
        """
        returns the values of the dictionary
        """
        for element in dictionary:
            yield dictionary[element]

    @staticmethod
    def inverse(dictionary: dict) -> dict:
        """
        inverses the dictionary (so values become indexes and opposite)
        """
        x = dict()
        for element in dictionary:
            x[dictionary[element]] = element
        return x

    @staticmethod
    def sort(dictionary: dict, key=sorted) -> dict:
        """
        sort dictionary by indexes
        """
        return {Index: dictionary[Index] for Index in key(list(dictionary))}


class Const:
    def __init__(self, val: typing.Any) -> None:
        """
        create deepcopy of list (cause python is strange and source lists are dependent on it's cloned lists)
        
        also works with other variable types
        """
        self.value = copy.deepcopy(val)
    
    def __repr__(self) -> str:
        return str(self.value)

    def get(self):
        """
        return value with an extra deep copy
        """
        return copy.deepcopy(self.value)
    
    def len(self) -> int:
        """
        return length of list (cause why not?)
        """
        return len(self.value)


def arrange(*args) -> types.GeneratorType:
    """
    basically like numpy.arrange (range with float as steps) but with rounded output
    """
    def_args = [0.0, None, 1.0]
    if len(args) == 1:    # if only one argument is given, map it to element 1
        def_args[1] = args[0]
    else:
        for i in range(len(args)):  # else exchange each element with its corresponding new value
            def_args[i] = args[i]

    x = def_args[0]  # set start position of x
    while x < def_args[1]:
        yield float(round(x, len(str(def_args[2]).split('.')[1])))  # return x (rounded based on how many decimals the step variable has)
        x += def_args[2]  # add step to x


def inverse(value: bool | int | str) -> bool | int | str:
    """
    inverse a bool or int (or technically also a str) object
    """
    t = type(value)  # type for final conversion
    val = bool(value)   # bool value so we don't need to handle every single variable type
    if not val:  # inverse
        val = True
    else:
        val = False
    return t(val)   # return converted value


def timeit(func) -> typing.Callable:
    """
    when calling function, add argument "times"

    it will loop this function for the given number,

    then return the result in seconds
    """
    def wrapper(times: int, *args, **kw) -> float:
        start = time.time()
        for _ in range(times):
            func(*args, **kw)
        return time.time()-start

    return wrapper

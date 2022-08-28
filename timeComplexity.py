import time
import random
import copy
def insertSort(list):
        data = copy.deepcopy(list)
        for j in range(1, len(data)):
            for i in range(j, 0, -1):
                if data[i] < data[i-1]:
                    data[i], data[i-1] = data[i-1], data[i]
                else:
                    break
        return data


def mergeSort(list1):
    size = len(list1)
    middle = size // 2
    if size > 1:      

        left = list1[:middle]
        right = list1[middle:]
        mergeSort(left)
        mergeSort(right)

        i = 0   #left index
        j = 0   #right index
        k = 0   #mergeSort index
        while i < len(left) and j < len(right):

            if left[i] < right[j]:
                list1[k] = left[i]
                i = i + 1
            else:
                
                list1[k] = right[j]
                j = j + 1
            k = k + 1
        while i < len(left):
            list1[k] = left[i]
            i = i + 1
            k = k + 1
        while j < len(right):
            list1[k] = right[j]
            j = j + 1
            k = k + 1

    else:
        return list1



def quickSort(list2):
    length = len(list2)
    if length <= 1:
        return list2
    else:
        pivot = list2.pop()
    greater = []
    lower = []

    for item in list2:
        if item > pivot:
            greater.append(item)
        else:
            lower.append(item)
    return quickSort(lower) + [pivot] + quickSort(greater)




for l in range (0,3,1):
    list = [i for i in range(1000)]
    random.shuffle(list)
    list1 = [j for j in range(1000)]
    random.shuffle(list1)
    list2 = [k for k in range(1000)]
    random.shuffle(list2)


    start = time.perf_counter()
    insertSort(list)
    insertSort_time = time.perf_counter() - start

    start = time.perf_counter()
    mergeSort(list1)
    mergeSort_time = time.perf_counter() - start

    start = time.perf_counter()
    quickSort(list2)
    quickSort_time = time.perf_counter() - start



    print('insertsort : ', l, ' - >', insertSort_time)
    print('mergeSort :  ', l, ' - >' ,mergeSort_time)
    print('quickSort :  ', l, ' - >' ,quickSort_time)
    print('\n')


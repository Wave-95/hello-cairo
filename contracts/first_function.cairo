#The arr argument is a reference to the value of the pointer.
# arr + 1 would grab the second element within the array.
#In a size=1 array where arr = [5]...there will be 1 recursive call with sum_of_rest returning a value of 0.
#The return value of the original function would then be sum=5 + 0.

func array_sum(arr : felt*, size) -> (sum):
    if size == 0:
        return (sum = 0)
    end

    let (sum_of_rest) = array_sum(arr=arr + 1, size=size - 1)
    return (sum=[arr] + sum_of_rest)
end
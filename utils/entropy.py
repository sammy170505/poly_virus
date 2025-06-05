from math import log2

def entropy(data):
    """Calculate the Shannon entropy of a dataset."""
    if not data:
        return 0

    # Count the frequency of each unique item in the data
    frequency = {}
    for item in data:
        frequency[item] = frequency.get(item, 0) + 1

    # Calculate the entropy
    total_items = len(data)
    ent = 0.0
    for count in frequency.values():
        probability = count / total_items
        ent -= probability * log2(probability)

    return ent
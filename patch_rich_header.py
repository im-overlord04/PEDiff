

def my_get_rich_info(rich_header):
    if rich_header is None:
        return None

    # Get list of @Comp.IDs and counts from Rich header
    # Elements in rich_fields at even indices are @Comp.IDs
    # Elements in rich_fields at odd indices are counts
    rich_fields = rich_header.get("values", None)
    if len(rich_fields) % 2 != 0:
        return None

    richinfos = []
    compid = None
    for i in rich_fields:
        if rich_fields.index(i) % 2 == 0:
            #even -> save value
            compid = get_rich_idVersion(i)
        else:
            #odd -> add to list
            if compid:
                richinfos.append(compid + " count=%d" % i)
                compid = None

    # Close PE file and return Rich Header information
    return '\n'.join(richinfos)
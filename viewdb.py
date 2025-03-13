import sqlite3

def print_database():
    conn = sqlite3.connect("packetsdatabase.db", detect_types=sqlite3.PARSE_DECLTYPES)
    cursor = conn.cursor()
    cursor.execute("""select * from packets""")
    rows = cursor.fetchall()
    headings = [description[0] for description in cursor.description]
    print("\t".join(headings))

    for row in rows:
        print("\t".join(str(item) if item is not None else 'NULL' for item in row))
    conn.commit()
    conn.close()


print_database()
    

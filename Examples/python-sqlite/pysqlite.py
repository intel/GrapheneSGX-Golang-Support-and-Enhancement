#!/usr/bin/env python3

import cProfile
import argparse
import os.path
import sqlite3 as db
import csv

class SqliteDB(object):
    CREATE_SQL = """CREATE TABLE IF NOT EXISTS songs (
            ID     INTEGER  PRIMARY KEY AUTOINCREMENT,
            Name   TEXT     NOT NULL,
            Rating TEXT     NOT NULL
            )"""
    DROP_SQL   = "DROP TABLE songs"
    INSERT_SQL = "INSERT INTO songs VALUES ( NULL, ?, ? )"
    SELECT_SQL = "SELECT * FROM songs"
    DELETE_SQL = "DELETE FROM songs"
    UPDATE_UPPER_SQL = "UPDATE songs SET Name = upper(Name)"
    UPDATE_LOWER_SQL = "UPDATE songs SET Name = lower(Name)"

    def __init__(self, dbFile):

        self.dbFile = dbFile
        self.conn = None
        self.cur = None

        createDB = not os.path.exists(dbFile)
        if createDB:
            print( 'Sqlite database does not exist' )

        try:
            self.conn  = db.connect(dbFile)
            if createDB:
                print( 'Sqlite database file {} created'.format(dbFile))
            self.cur = self.conn.cursor()
            print( 'Sqlite database is opened')
            cur = self.create_table()
            if cur is not None:
                print( 'Table created' )
        except Error as e:
            print(e)

    def load_csv(self, csvFileReader):
        for row in csvFileReader:
            cur = self.query(self.INSERT_SQL, row.strip().split(','))
            if cur is None:
                print( 'Insert record failed' )

    def show_all(self):
        cur = self.query(self.SELECT_SQL, [])
        if cur:
            for row in cur:
                print(row)

    def delete_all(self):
        cur = self.query(self.DELETE_SQL, [])
        if cur is None:
            print( 'Delete record failed' )
        return cur

    def update_upper_all(self):
        cur = self.query(self.UPDATE_UPPER_SQL, [])
        if cur is None:
            print( 'Update record as upper case failed' )
        return cur

    def update_lower_all(self):
        cur = self.query(self.UPDATE_LOWER_SQL, [])
        if cur is None:
            print( 'Update record as lower case failed' )
        return cur

    def query(self, sqlcmd , args):
        if self.cur:
            try:
                print ("Query : {}, Params : {}".format(sqlcmd, str(args)))
                self.cur.execute(sqlcmd, args)
                self.conn.commit()
                return self.cur
            except Error as e:
                print(e)

    def create_table(self):
        cur = self.query(self.CREATE_SQL, [])
        if cur is None:
            print( 'Create table failed or the table exists' )
        return cur

    def drop_table(self):
        cur = self.query(self.DROP_SQL, [])
        if cur is None:
            print( 'Drop table failed' )
        return cur

    def delete_db(self):
        self.drop_table()
        os.remove(self.dbFile)
        print ( 'Sqlite database file is deleted' );

    def __del__(self):
        if self.conn:
            self.conn.close()
            print( 'Sqlite database is closed')

if __name__ == '__main__':

    inFileName = "songs.csv"
    dbFileName = "sqlite_songs.db"
    perfFileName = "sqlite_result.prof"
    updateCount = 10

    def main(args):
        with args.dbfn as dbfn:
            o = SqliteDB(dbfn.name)
        with args.infn as infn:
            o.load_csv(infn);
        o.show_all();
        for v in range(args.count):
            o.update_upper_all();
            o.show_all();
            o.update_lower_all();
            o.show_all();
        if args.deldb:
            o.delete_all();
            o.delete_db();

    parser = argparse.ArgumentParser(description='Validate the Sqlite database operations.')
    parser.add_argument('-c', type=int, dest="count", default=updateCount, metavar='count',
                                        help='The number of data update (default: %(default)s)')

    parser.add_argument('-i', dest="infn", type=argparse.FileType('rt'), metavar='in-file',
                        default=inFileName, help='The input csv file (default: %(default)s)')
    parser.add_argument('-o', dest="dbfn", type=argparse.FileType('a+b'), metavar='db-file',
                        default=dbFileName, help='The sqlite database file (default: %(default)s)')
    parser.add_argument('-p', dest="pffn", type=argparse.FileType('wb'), metavar='perf-file',
                        default=perfFileName, help='The sqlite perf. file (default: %(default)s)')
    parser.add_argument('-d', dest="deldb", action='store_true',
                        help='Destroy sqlite db & its file after run')
    try:
        args = parser.parse_args()
    except IOError as e:
        parser.error(e);

    pr = cProfile.Profile()
    pr.enable()
    main(args)
    pr.disable()
    pr.print_stats()
    with args.pffn as pffn:
        pr.dump_stats(pffn.name)

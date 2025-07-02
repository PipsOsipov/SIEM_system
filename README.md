PIPS_SIEM is a lightweight log monitoring and analysis system focused on security and compliance. The system is designed for centralized analysis of data from various sources such as servers and endpoints.

It provides:
    1. Real-time log collection and normalization.
    2. Tracking changes to system files and configurations.

User-guide:
  1. Installing DB PostgreSQL(Linux cause it's server-side)

     sudo apt update && sudo apt upgrade

     sudo apt install postgresql postgresql-contrib
     
  2. After installing you should creat new user and database
     in terminal:

       su - postgres

       psql

       /q (for exit)
    
     under the postgres user:
    
       CREATE USER <user_name> WITH PASSWORD <'password'>;
    
       CREATE DATABASE <db_name> OWNER <user_name>;   
  
  4. Then you can create some tables in your database

     in terminal:
       psql -U <user_name> -d <db_name> -h localhot(or another address)
     in user:
       CREATE TABLE <table_name>(id SERIAL PK, ... other fields you need);
       #DROP TABLE <table_name> (for deleting table)

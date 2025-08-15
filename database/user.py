# from sqlalchemy import Column,Integer,String,create_engine
# from sqlalchemy.ext.declarative import declarative_base
# from sqlalchemy.orm import sessionmaker


# engine=create_engine('sqlite:///users.db',echo=True)
# Base=declarative_base()
# Session=sessionmaker(bind=engine)
# session=Session()

# class Users(Base):
#     __tablename__ ='users'

#     id=Column(Integer,primary_key=True)
#     username=Column(String,unique=True,nullable=False)
#     password=Column(String,nullable=False)


#     def __repr__(self):
#         return f"<User(username='{self.username})>'"

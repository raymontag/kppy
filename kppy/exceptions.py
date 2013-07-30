class KPError(Exception):
    """KPError is a exception class to handle exception raised by KPDB.
    
    Usage:
    
    Handle KPError like every else expection. You can print the error message
    via an expection instance.
    
    Example:
    
    try:
        ...
    except KPError as e:
        print(e)
        
    """

    def __init__(self, error):
        self.msg = error

    def __str__(self):
        return ("KPError: "+self.msg)


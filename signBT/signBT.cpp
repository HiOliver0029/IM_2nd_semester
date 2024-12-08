#include <Python.h>

int main(int argc, char **argv){
    Py_Initialize();
    PyObject * obj = Py_BuildValue("s", "signBT.py");
    FILE * fp = _Py_fopen_obj(obj, "r+");
    if(fp != NULL)
        PyRun_SimpleFile(fp, "signBT.py");

    Py_Finalize();
    return 0;
}
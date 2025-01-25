import java.io.*;
import java.util.*;

public class Main {
    public static void main(String[] args) {
        FileHandler fileHandler = new FileHandler();
        fileHandler.readFile("sample.txt");
        
        Utils.printHello();
    }
}

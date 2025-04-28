import java.io.*;
import java.util.*;

API_KEY = "dsbjbsgiubwefihbewbvfwufvhvfyyevhvefou"

public class Main {
    public static void main(String[] args) {
        FileHandler fileHandler = new FileHandler();
        fileHandler.readFile(API_KEY);
        
        Utils.printHello();
    }
}

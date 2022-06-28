#include <cstdio>
#include <cerrno>

/**Structure representing file stream.
*Places own data safety at first place.
*Use open to open file and close to close it.
*Every file stream has defined constants mode, binary, path, end, point, error.
*/
template<class path_type = char>
struct fileStream
{
    protected:
        //Secure storage, inaccessible from outside.

        ///File storage.
        FILE* file = nullptr;

        ///Mode storage.
        unsigned short privateMode = 0;

        ///Binary mode storage;
        unsigned short privateBinaryMode = false;

        ///Error storage.
        int privateError = 0;

        ///Pointer storage.
        unsigned long long filePointer = 0;

        ///Current path storage.
        path_type* privatePath = nullptr;

        bool privateEndOfFile = false;
    
    private:
        //Secure secret functions storage.

        //Functions from other libraries.

        //Checks whenever it contains zero given its real or expected size.
        bool isStringZeroTerminated(const char* string, unsigned long long expectedSize = 0)
        {
            for(unsigned long long i = 0; i < expectedSize; ++i)
            {
                if(string[i] == '\0')
                {
                    return true;
                }
            }
            return false;
        }

        //Protects from "(Function name) doesn't handle strings that are not '\0'-terminated; if given one it may perform an over-read (it could cause a crash if unprotected) (CWE-126)."
        void ensureZeroTerminated(char* string, unsigned long long expectedSize = 0)
        {
            if(not isStringZeroTerminated(string, expectedSize))
            {
                string[expectedSize - 1] = '\0';
            }
        }

        ///Copy list into another list.
        template<class type>
        void copyList(const type copiedlist[], type list[], unsigned long long size)
        {
            for(unsigned long long i = 0; i < size; ++i)
            {
                list[i] = copiedlist[i];
            }
        }

        ///Adds element to list. Returns list with new element.
        template<class type>
        void addToList(type* &list, unsigned long long size, type newElement)
        {
            type* extendedList = new type[size + 1];
            for(unsigned long long i = 0; i < size; ++i)
            {
                extendedList[i] = list[i];
            }
            delete[] list;
            extendedList[size] = newElement;
            list = extendedList;
        }

        ///Returns length of the string.
        template<class type>
        unsigned long long stringLength(const type* string)
        {
            //for(unsigned long long i = 0; string[i] != '\0'; ++i)
            unsigned long long i = 0;
            while(string[i] != '\0')
            {
                ++i;
            }
            return i;
        }

        ///Returns copy of string.
        char* stringCopy(const char* string)
        {
            char* newString = new char[stringLength(string) + 1];
            copyList(string, newString, stringLength(string) + 1);
            return newString;
        }
        
        //Clears default error variables to collect new error messages.
        void clearErrorPointing()
        {
            clearerr(file);
            errno = 0;
        }

        bool isError()
        {
            return (ferror(file) != 0) or (errno != 0);
        }

        int extractError()
        {
            if(ferror(file) != 0)
            {
                return ferror(file);
            }
            else if(errno != 0)
            {
                return errno;
            }
            else
            {
                return privateError;
            }
        }

        ///Updates End Of File information to insure, that clearerr can't remove end of file data.
        void updateEndOfFile()
        {
            privateEndOfFile = (privateEndOfFile)?(true):(feof(file));
        }

        ///Checks whenever stream is open.
        bool isStreamOpen()
        {
            return file != nullptr and privateMode == 0;
        }

        ///Checks whenever stream is valid for reading.
        bool isValidForReading()
        {
            return file != nullptr and !privateEndOfFile and (privateMode == 1 or (privateMode >= 4 and privateMode <= 6));
        }

        //Checks whenever stream is valid for writing.
        bool isValidForWriting()
        {
            return file != nullptr and (privateMode >= 2 and privateMode <= 6);
        }

        ///Checks whenever stream is valid for reading.
        bool isValidForTextReading()
        {
            return file != nullptr and !privateEndOfFile and (privateMode == 1 or (privateMode >= 4 and privateMode <= 6)) and !privateBinaryMode;
        }

        //Checks whenever stream is valid for writing.
        bool isValidForTextWriting()
        {
            return file != nullptr and (privateMode >= 2 and privateMode <= 6) and !privateBinaryMode;
        }

        ///Checks whenever stream is valid for binary reading.
        bool isValidForBinaryReading()
        {
            return file != nullptr and !privateEndOfFile and (privateMode == 1 or (privateMode >= 4 and privateMode <= 6)) and privateBinaryMode;
        }

        ///Checks whenever stream is valid for binary writing.
        bool isValidForBinaryWriting()
        {
            return file != nullptr and (privateMode >= 2 and privateMode <= 6) and privateBinaryMode;
        }

        //Checks whenever strings are same.
        bool isStringsEqual(const char* string1, const char* string2)
        {
            if(stringLength(string1) != stringLength(string2))
            {
                return false;
            }
            return equalList(string1, string2, stringLength(string2));
        }

    public:
        //Data, available to anything outside structure.

        ///Default error code of all functions.
        const static unsigned short defaultErrorCode = 1;
        //const unsigned short defaultErrorCode = 1; //Invalid use of non-static data member 'defaultErrorCode' (non static? Hm...)

        ///Opened file mode. 1 = read; 2 = write; 3 = append; 4 = read and write, but file must exist; 5 = read and write; 6 = read and append. Uneditable from outside.
        const unsigned short &mode = privateMode;

        ///Is binary mode used.
        const unsigned short &binary = privateBinaryMode;

        ///Last error storage. Uneditable from outside.
        const int &error = privateError;

        ///Point where file currently read or written.
        const unsigned long long &point = filePointer;

        ///Securely stored unchangeable path to current file.
        const path_type* const path = privatePath;

        ///Checks whenever it is end of file.
        const bool &end = privateEndOfFile;

        ///Cleans errors history.
        void clean_error()
        {
            clearErrorPointing();
            privateError = 0;
        }

        ///Function to send error to another function.
        void handle(bool(handlingFunction)(const unsigned short &))
        {
            if(!isError())
            {
                return;
            }
            bool shouldClose = handlingFunction(extractError());
            if(shouldClose)
            {
                close();
            }
        }

        ///Returns error and clears last error history.
        int getError()
        {
            int returned = error;
            clean_error();
            return returned;
        }

        /*Returns file pointer and automatically closes file stream.
        Caution! Pointer goes out of file stream scope. File stream will be closed after this operation automatically to prevent non library-dependent and broken behavoir.*/
        FILE* extractPointer()
        {
            privateMode = 0;
            privateBinaryMode = false;
            filePointer = 0;
            if(privatePath != nullptr)
            {
                delete[] privatePath;
                privatePath = nullptr;
            }
            FILE* savedFile = file;
            file = nullptr;
            privateEndOfFile = false;
            return savedFile;
        }

        /**Opens stream with choosen parameters.
        *Opening mode supports one of the 6 values. Those are:
        *1 - read only;
        *2 - write only;
        *3 - append only;
        *4 - read and write, but file should exist;
        *5 - read and write, but file will be created;
        *6 - read and append.
        *To choose whenever or not use binary mode use third bool parameter.
        */
        void open(const path_type* const choosenPath, unsigned short openingMode, bool binaryMode = false, int errorCode = defaultErrorCode)
        {
            if(choosenPath == nullptr or isStreamOpen())
            {
                //Ensure nothing will be broken.
                privateError = errorCode;
                return;
            }
            //assert(file);
            switch(openingMode)
            {
                default: privateError = errorCode; return;
                case 1: file = fopen(choosenPath, (binaryMode)?("rb"):("r")); break;
                case 2: file = fopen(choosenPath, (binaryMode)?("wb"):("w")); break;
                case 3: file = fopen(choosenPath, (binaryMode)?("ab"):("a")); break;
                case 4: file = fopen(choosenPath, (binaryMode)?("rb+"):("r+")); break;
                case 5: file = fopen(choosenPath, (binaryMode)?("wb+"):("w+")); break;
                case 6: file = fopen(choosenPath, (binaryMode)?("ab+"):("a+")); break;
            }
            if(file == nullptr)
            {
                privateError = extractError();
                return;
            }
            privateBinaryMode = binaryMode;
            privateMode = openingMode;
            privatePath = stringCopy(choosenPath);
            updateEndOfFile();
        }

        /**Closes stream. No parameters needed.
        *Can and must be called even if the stream has been corrupted.
        */
        void close()
        {
            if(file != nullptr)
            {
                fclose(file);
                file = nullptr;
            }
            privateMode = 0;
            privateBinaryMode = false;
            //privateError = 0; //No need to clear last error log.
            filePointer = 0;
            privateEndOfFile = false;
            if(privatePath != nullptr)
            {
                delete[] privatePath;
                privatePath = nullptr;
            }
        }

        ///Close file stream automatically during destruction.
        ~fileStream()
        {
            close();
        }

        ///Reopen file at the same path but in different mode.
        void reopen(unsigned short openingMode, bool binaryMode = false, int errorCode = defaultErrorCode)
        {
            if(!isStreamOpen())
            {
                privateError = errorCode;
                return;
            }
            switch(openingMode)
            {
                default: privateError = errorCode; return;
                case 1: file = freopen(path, (binaryMode)?("rb"):("r")); break;
                case 2: file = freopen(path, (binaryMode)?("wb"):("w")); break;
                case 3: file = freopen(path, (binaryMode)?("ab"):("a")); break;
                case 4: file = freopen(path, (binaryMode)?("rb+"):("r+")); break;
                case 5: file = freopen(path, (binaryMode)?("wb+"):("w+")); break;
                case 6: file = freopen(path, (binaryMode)?("ab+"):("a+")); break;
            }
            if(file == nullptr or isError())
            {
                privateError = extractError();
                return;
            }
            privateBinaryMode = binaryMode;
            privateMode = openingMode;
            filePointer = 0;
        }

        /**Function to read character, which supports binary mode.
        *You can specify type for read characters(char, char16_t, char32_t) as following:
        *fileStreamName.getCharacter<type>();
        */
        template<class type = path_type>
        type getCharacter(int errorCode = defaultErrorCode)
        {
            if(!isValidForReading())
            {
                privateError = errorCode;
                return '\0';
            }
            if(privateBinaryMode)
            {
                type data = *readBlock<type>(1);
                privateError = extractError();
                if(isError())
                {
                    privateError = extractError();
                    clearErrorPointing();
                    return '\0';
                }
                updateEndOfFile();
                return data;
            }
            else
            {
                ++filePointer;
                type character = fgetc(file);
                if(isError())
                {
                    privateError = extractError();
                    clearErrorPointing();
                    return '\0';
                }
                updateEndOfFile();
                return character;
            }
        }

        /**Reads specific amount of text. Places '\0' in the end of the string.
        *You can specify type for read characters(char, char16_t, char32_t) as following:
        *fileStreamName.getString<type>();
        */
        template<class type = path_type>
        type* getString(unsigned long long neededSize, int errorCode = defaultErrorCode)
        {
            if(!isValidForReading())
            {
                privateError = errorCode;
                return "";
            }
            type* line = nullptr;
            unsigned long long size = 0;
            for(unsigned long long i = 0; i < neededSize and !privateEndOfFile; ++i)
            {
                type checkedCharacter = getCharacter<type>();
                if(checkedCharacter == '\0')
                {
                    //privateError = errorCode; //Error already tracked.
                    delete[] line;
                    return "";
                }
                addToList(line, size, checkedCharacter);
                ++size;
            }
            addToList(line, size, '\0');
            return line;
        }

        /**Gets line of file. Assumes, that pointer placed at the start of the line. Replaces '\n' in the end with '\0'.
        *You can specify type for read characters(char, char16_t, char32_t) as following:
        *fileStreamName.getLine<type>();
        */
        template<class type = path_type>
        type* getLine(int errorCode = defaultErrorCode)
        {
            if(!isValidForReading())
            {
                privateError = errorCode;
                return "";
            }
            type* line = nullptr;
            unsigned long long size = 0;
            while(true)
            {
                type checkedCharacter = getCharacter<type>();
                if(checkedCharacter == '\0')
                {
                    //privateError = errorCode; //Error already tracked.
                    delete[] line;
                    return "";
                }
                if(checkedCharacter == '\n')
                {
                    addToList(line, size, '\0');
                    //++size; //Variable 'size' is assigned a value that is never used. CppCheck
                    break;
                }
                addToList(line, size, checkedCharacter);
                ++size;
            }
            return line;
        }

        /**Gets all content of the file.
        *You can specify type for read characters(char, char16_t, char32_t) as following:
        *fileStreamName.getFile<type>();
        */
        template<class type = path_type>
        type* getFile(int errorCode = defaultErrorCode)
        {
            if(!isValidForReading())
            {
                privateError = errorCode;
                return "";
            }
            type* line = nullptr;
            unsigned long long size = 0;
            while(!privateEndOfFile)
            {
                type checkedCharacter = getCharacter<type>();
                if(checkedCharacter == '\0')
                {
                    //privateError = errorCode; //Error already tracked.
                    delete[] line;
                    return "";
                }
                addToList(line, size, checkedCharacter);
                ++size;
            }
            addToList(line, size, '\0');
            return line;
        }

        /**Function to write character, which supports binary mode.
        *You can specify type for written characters(char, char16_t, char32_t).
        *The syntax is following:
        *fileStreamName.writeCharacter<type>(character to add);
        */
        template<class type>
        void writeCharacter(const type character, int errorCode = defaultErrorCode)
        {
            if(!isValidForWriting())
            {
                privateError = errorCode;
                return;
            }
            if(privateBinaryMode)
            {
                writeBlock(*character, 1);
                if(isError())
                {
                    privateError = extractError();
                    clearErrorPointing();
                    return;
                }
            }
            else
            {
                ++filePointer;
                fputc(character, file);
                if(isError())
                {
                    privateError = extractError();
                    clearErrorPointing();
                    return;
                }
            }
            updateEndOfFile(); //Only character function needs that.
        }

        /**Function to write string to file, which supports binary mode.
        *You can specify type for written characters(char, char16_t, char32_t).
        *The syntax is following:
        *fileStreamName.writeString<type>(string to add, expected size(unnecessary));
        */
        template<class type>
        void writeString(const type* string, unsigned long long expectedSize = 0, int errorCode = defaultErrorCode)
        {
            if(!isValidForWriting() or !isStringZeroTerminated(string, expectedSize))
            {
                privateError = errorCode;
                return;
            }
            int savedError = privateError;
            unsigned long long stringPlace = 0;
            while(string[stringPlace] != '\0')
            {
                writeCharacter<type>(string[stringPlace]);
                if(privateError != savedError)
                {
                    return;
                }
                ++stringPlace;
            }
        }

        /**Function to write line, which supports binary mode.
        *After writing line, goes to next line.
        *You can specify type for written characters(char, char16_t, char32_t).
        *The syntax is following:
        *fileStreamName.writeLine<type>(string to add, expected size(unnecessary));
        */
        template<class type>
        void writeLine(const type* string, unsigned long long expectedSize = 0, int errorCode = defaultErrorCode)
        {
            if(!isValidForWriting() or !isStringZeroTerminated(string, expectedSize))
            {
                privateError = errorCode;
                return;
            }
            int savedError = privateError;
            unsigned long long stringPlace = 0;
            while(string[stringPlace] != '\0')
            {
                writeCharacter<type>(string[stringPlace]);
                if(privateError != savedError)
                {
                    return;
                }
                ++stringPlace;
            }
            writeCharacter('\n');
            if(privateError != savedError)
            {
                return;
            }
        }

        /**Function, which resets file to zero position.
        *Syntax is following:
        *fileStreamName.reset()
        */
        void reset(int errorCode = defaultErrorCode)
        {
            if(privateMode == 3 or !isStreamOpen())
            {
                privateError = errorCode;
                return;
            }
            filePointer = 0;
            privateEndOfFile = false;
            rewind(file);
            if(isError())
            {
                privateError = extractError();
                clearErrorPointing();
                return;
            }
            updateEndOfFile();
        }

        /**Function, which will attempt to move pointer to choosen place.
        *Syntax is following:
        *fileStreamName.pointTo(place in file, from where to start)
        *We can start from the:
        *1 - start;
        *2 - current position;
        *3 - end position.
        *If your system supports so you can use:
        *4 - SEEK_DATA;
        *5 - SEEK_HOLE.
        */
        void pointTo(int pointer, unsigned short from = 1, int errorCode = defaultErrorCode)
        {
            if(privateMode == 3 or !isStreamOpen())
            {
                privateError = errorCode;
                return;
            }
            switch(from)
            {
                default: privateError = errorCode; return;
                case 1: fseek(file, pointer, SEEK_SET); break;
                case 2: fseek(file, pointer, SEEK_CUR); break;
                case 3: fseek(file, pointer, SEEK_END); break;
                #ifdef _GNU_SOURCE
                case 4: fseek(file, pointer, SEEK_DATA); break;
                case 5: fseek(file, pointer, SEEK_HOLE); break;
                #endif
            }
            
            if(isError())
            {
                privateError = extractError();
                clearErrorPointing();
                return;
            }
            updateEndOfFile();
            filePointer = ftell(file);
        }

        ///Returns size of a file.
        unsigned long long size(int errorCode = defaultErrorCode)
        {
            if(privateMode == 3 or !isStreamOpen())
            {
                privateError = errorCode;
                return 0;
            }
            unsigned long long current = ftell(file);
            fseek(file, 0, SEEK_END);
            unsigned long long returned = ftell(file);
            fseek(file, current, SEEK_SET);
            if(isError())
            {
                privateError = extractError();
                clearErrorPointing();
                return 0;
            }
            return current;
        }

        /**Function which reads in fprintf/fscanf format. Requires pointers to variables, not variables itself.
        *You can specify type for format characters(char, char16_t, char32_t).
        *Syntax is following:
        *fileStreamName.getBtFormat<type>(format, pointers to all variables to which result will be written);
        */
        template<class type, class... Arguments>
        int getByFormat(const type* const format, Arguments*... arguments)
        {
            if(!isValidForTextReading())
            {
                privateError = defaultErrorCode;
                return 0;
            }
            //If format strings can be influenced by an attacker, they can be exploited (CWE-134). Use a constant for the format specification.
            int processedInt = fscanf(file, format, arguments...);
            if(isError())
            {
                privateError = extractError();
                clearErrorPointing();
                return privateError;
            }
            filePointer = ftell(file);
            updateEndOfFile();
            if(processedInt < 0)
            {
                privateError = (unsigned short)processedInt;
                return 0;
            }
            else if(isError())
            {
                privateError = extractError();
                clearErrorPointing();
                return privateError;
            }
            else
            {
                return processedInt;
            }
        }

        /**Function which writes in fprintf/fscanf format. Requires variables.
        *You can specify type for format characters(char, char16_t, char32_t).
        *Syntax is following:
        *fileStreamName.writeByFormat<type>(format, pointers to all variables values of which will be written);
        */
        template<class type, class... Arguments>
        int writeByFormat(const type* const format, Arguments... arguments)
        {
            if(!isValidForTextWriting())
            {
                privateError = defaultErrorCode;
                return 0;
            }
            //If format strings can be influenced by an attacker, they can be exploited (CWE-134). Use a constant for the format specification.
            int processedInt = fprintf(file, format, arguments...);
            if(isError())
            {
                privateError = extractError();
                clearErrorPointing();
                return privateError;
            }
            filePointer = ftell(file);
            updateEndOfFile();
            if(processedInt < 0)
            {
                privateError = (unsigned int)processedInt;
                return 0;
            }
            else if(isError())
            {
                privateError = extractError();
                clearErrorPointing();
                return privateError;
            }
            else
            {
                return processedInt;
            }
        }

        /**Function which reads in binary.
        *Syntax is following:
        *fileStreamName.readBlock<type of read value>(number of elements);
        */
        template<class type>
        type* readBlock(unsigned long long count, unsigned long long errorCode = defaultErrorCode)
        {
            if(!isValidForBinaryReading())
            {
                privateError = errorCode;
                return nullptr;
            }
            type* pointer = new type[count];
            unsigned long long result = fread(pointer, sizeof(type), count, file);
            if(isError())
            {
                privateError = extractError();
                clearErrorPointing();
                delete[] pointer;
                return nullptr;
            }
            filePointer = ftell(file);
            updateEndOfFile();
            if(result == 0 or isError())
            {
                privateError = extractError();
                clearErrorPointing();
                delete[] pointer;
                return nullptr;
            }
            return pointer;
        }

        /**Function which reads in binary.
        *Syntax is following:
        *fileStreamName.writeBlock<type of written value, unnecessary>(pointer to written element, number of elements);
        */
        template<class type>
        void writeBlock(type* pointer, unsigned long long count, unsigned long long errorCode = defaultErrorCode)
        {
            if(!isValidForBinaryWriting())
            {
                privateError = errorCode;
                return;
            }
            unsigned long long result = fwrite(pointer, sizeof(type), count, file);
            if(isError())
            {
                privateError = extractError();
                clearErrorPointing();
                return;
            }
            if(result == 0)
            {
                privateError = errorCode;
                return;
            }
            filePointer = ftell(file);
            if(isError())
            {
                privateError = extractError();
                clearErrorPointing();
                return;
            }
            updateEndOfFile();
        }

        ///Compare two file streams.
        template<class type>
        inline bool operator==(const fileStream& file)
        {
            return (isStringsEqual(file.path, path) and (file.mode == mode) and (file.binary == binary));
        }

        ///Opens new file stream with the same parameters as old.
        template<class type>
        fileStream<type> operator=(const fileStream<type>& file)
        {
            fileStream<type> newStream;
            if(file.path != nullptr and file.mode != 0)
            {
                newStream.open(file.path, file.mode, file.binary);
            }
            return newStream;
        }
};

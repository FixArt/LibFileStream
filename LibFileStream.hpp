#include <cstdio>
#include <cerrno>
#include <climits>
//#include <sys/param.h>
//#include <iostream>

/**Structure representing file stream.
*Places own data safety at first place.
*Use open to open file and close to close it.
*Every file stream has defined constants mode, binary, path, end, error.
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

        ///Current path storage.
        path_type* privatePath = nullptr;

        bool privateEndOfFile = false;
    
    private:
        //Secure secret functions storage.

        //Functions from other libraries.

        //Checks whenever it contains zero given its real or expected size.
        template<class type>
        static bool isStringZeroTerminated(const type* string, unsigned long long expectedSize = 0)
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
        template<class type>
        static void ensureZeroTerminated(type* string, unsigned long long expectedSize = 0)
        {
            if(not isStringZeroTerminated<type>(string, expectedSize))
            {
                string[expectedSize - 1] = '\0';
            }
        }

        ///Copy list into another list.
        template<class type>
        static void copyList(const type copiedlist[], type list[], unsigned long long size)
        {
            for(unsigned long long i = 0; i < size; ++i)
            {
                list[i] = copiedlist[i];
            }
        }

        ///Adds element to list. Returns list with new element.
        template<class type>
        static void addToList(type* &list, unsigned long long size, type newElement)
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
        static unsigned long long stringLength(const type* string)
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
        template<class type>
        type* stringCopy(const type* string)
        {
            type* newString = new type[stringLength(string) + 1];
            copyList<type>(string, newString, stringLength(string) + 1);
            return newString;
        }

        bool isError()
        {
            return (ferror(file) != 0) or (errno != 0);
        }
        
        //Clears default error variables to collect new error messages.
        void clearErrorPointing()
        {
            if(ferror(file) or feof(file))
            {
                clearerr(file);
            }
            errno = 0;
        }

        int extractError()
        {
            if(isStreamOpen() and (ferror(file) != 0))
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
            return 0;
        }

        ///Updates End Of File information to insure, that clearerr can't remove end of file data.
        void updateEndOfFile()
        {
            if(point() >= size())
            {
                privateEndOfFile = true;
            }
            privateEndOfFile = (privateEndOfFile)?(true):(feof(file));
        }

        ///Checks whenever stream is open.
        bool isStreamOpen() const
        {
            return file != nullptr and privateMode != 0;
        }

        ///Checks whenever stream is valid for reading.
        bool isValidForReading() const
        {
            return file != nullptr and !privateEndOfFile and (privateMode == 1 or (privateMode >= 4 and privateMode <= 6));
        }

        //Checks whenever stream is valid for writing.
        bool isValidForWriting() const
        {
            return file != nullptr and (privateMode >= 2 and privateMode <= 6);
        }

        ///Checks whenever stream is valid for reading.
        bool isValidForTextReading() const
        {
            return file != nullptr and !privateEndOfFile and (privateMode == 1 or (privateMode >= 4 and privateMode <= 6)) and !privateBinaryMode;
        }

        //Checks whenever stream is valid for writing.
        bool isValidForTextWriting() const
        {
            return file != nullptr and (privateMode >= 2 and privateMode <= 6) and !privateBinaryMode;
        }

        ///Checks whenever stream is valid for binary reading.
        bool isValidForBinaryReading() const
        {
            return file != nullptr and !privateEndOfFile and (privateMode == 1 or (privateMode >= 4 and privateMode <= 6)) and privateBinaryMode;
        }

        ///Checks whenever stream is valid for binary writing.
        bool isValidForBinaryWriting() const
        {
            return file != nullptr and (privateMode >= 2 and privateMode <= 6) and privateBinaryMode;
        }

        //Checks whenever two lists are equal.
        template<class type>
        static bool equalList(const type list1[], const type list2[], unsigned long long size)
        {
            bool isEqual = true;
            for(unsigned long long i = 0; i < size; ++i)
            {
                if(list1[i] != list2[i])
                {
                    isEqual = false;
                    break;
                }
            }
            return isEqual;
        }

        //Checks whenever strings are same.
        template<class type>
        static bool isStringsEqual(const type* string1, const type* string2)
        {
            if(stringLength(string1) != stringLength(string2))
            {
                return false;
            }
            return equalList<type>(string1, string2, stringLength(string2));
        }

        ///Disallow unauthorized creation of file stream copies.
        fileStream<path_type>( const fileStream<path_type>&);

    public:
        //Data, available to anything outside structure.

        ///Allow sending file stream in correct way.
        fileStream<path_type>() = default;

        ///Default error code of all functions.
        const static unsigned short defaultErrorCode = 1;
        //const unsigned short defaultErrorCode = 1; //Invalid use of non-static data member 'defaultErrorCode' (non static? Hm...)

        ///Opened file mode. 1 = read; 2 = write; 3 = append; 4 = read and write, but file must exist; 5 = read and write; 6 = read and append. Uneditable from outside.
        const unsigned short &mode = privateMode;

        ///Is binary mode used.
        const unsigned short &binary = privateBinaryMode;

        ///Last error storage. Uneditable from outside.
        const int &error = privateError;

        ///Securely stored uneditable path to current file.
        const path_type* const &path = privatePath;

        ///Checks whenever it is end of file.
        const bool &end = privateEndOfFile;

        ///Cleans errors history.
        void cleanError()
        {
            if(isStreamOpen())
            {
                clearErrorPointing();
            }
            privateError = 0;
        }

        ///Cleans error and returns true if error is same as given error.
        bool ignoreError(const int &ignoredError)
        {
            if(privateError == ignoredError)
            {
                privateError = 0;
                return true;
            }
            else
            {
                return false;
            }
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

        ///Placement in file.
        unsigned long long point(int errorCode = defaultErrorCode)
        {
            if(!isStreamOpen())
            {
                privateError = errorCode;
                return 0;
            }
            if(mode == 3)
            {
                return 0;
            }
            return ftell(file);
        }

        ///Returns error and clears last error history. Warning! Function not failsafe, and will crash if unsuitable problems occur.
        int getError()
        {
            int returned = privateError;
            cleanError();
            return returned;
        }

        /*Returns file pointer and automatically closes file stream.
        Caution! Pointer goes out of file stream scope. File stream will be closed after this operation automatically to prevent non library-dependent and broken behavoir.*/
        FILE* extractPointer()
        {
            privateMode = 0;
            privateBinaryMode = false;
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
            //ensureZeroTerminated(choosenPath, PATH_MAX); ///Since no legal path bigger than this constant exists, we can succesfully cut any path bigger than this.
            if(!isStringZeroTerminated(choosenPath, PATH_MAX / (sizeof(path_type) * 8)))
            {
                //Either file too long or this isn't valid string.
                privateError = ENAMETOOLONG;
                return;
            }
            // if((openingMode == 1 or openingMode == 4) and !realpath(choosenPath, NULL))
            // {
            //     //Path nonexistant.
            //     //privateError = ENOENT;
            //     privateError = ENOTDIR;
            //     return;
            // }
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
            privatePath = stringCopy<path_type>(choosenPath);
            updateEndOfFile();
        }

        /**Closes stream. No parameters needed.
        *Can and must be called even if the stream has been corrupted.
        */
        void close()
        {
            if(file != nullptr)
            {
                //rewind(file);
                fclose(file);
                file = nullptr;
            }
            privateMode = 0;
            privateBinaryMode = false;
            //privateError = 0; //No need to clear last error log.
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

        /**Reopen file at the same path but in different mode.
        *Opening mode supports one of the 6 values. Those are:
        *1 - read only;
        *2 - write only;
        *3 - append only;
        *4 - read and write, but file should exist;
        *5 - read and write, but file will be created;
        *6 - read and append.
        *To choose whenever or not use binary mode use third bool parameter.
        */
        void reopen(unsigned short openingMode, bool binaryMode = false, int errorCode = defaultErrorCode)
        {
            if(!isStreamOpen())
            {
                privateError = errorCode;
                return;
            }
            clearErrorPointing(); //Ensure that only own reports will be reported.
            switch(openingMode)
            {
                default: privateError = errorCode; return;
                case 1: file = freopen(privatePath, (binaryMode)?("rb"):("r"), file); break;
                case 2: file = freopen(privatePath, (binaryMode)?("wb"):("w"), file); break;
                case 3: file = freopen(privatePath, (binaryMode)?("ab"):("a"), file); break;
                case 4: file = freopen(privatePath, (binaryMode)?("rb+"):("r+"), file); break;
                case 5: file = freopen(privatePath, (binaryMode)?("wb+"):("w+"), file); break;
                case 6: file = freopen(privatePath, (binaryMode)?("ab+"):("a+"), file); break;
            }
            if(file == nullptr or isError())
            {
                privateError = extractError();
                return;
            }
            privateBinaryMode = binaryMode;
            privateMode = openingMode;
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
            clearErrorPointing(); //Ensure that only own reports will be reported.
            if(privateBinaryMode)
            {
                type data = readVariable<type>();
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
            clearErrorPointing(); //Ensure that only own reports will be reported.
            type* line = nullptr;
            unsigned long long stringSize = 0;
            for(unsigned long long i = 0; i < neededSize and !privateEndOfFile; ++i)
            {
                type checkedCharacter = getCharacter<type>();
                if(checkedCharacter == '\0')
                {
                    //privateError = errorCode; //Error already tracked.
                    delete[] line;
                    return "";
                }
                addToList(line, stringSize, checkedCharacter);
                ++stringSize;
            }
            addToList(line, stringSize, '\0');
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
            clearErrorPointing(); //Ensure that only own reports will be reported.
            type* line = nullptr;
            unsigned long long stringSize = 0;
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
                    addToList(line, stringSize, '\0');
                    //++stringSize; //Variable 'stringSize' is assigned a value that is never used. CppCheck
                    break;
                }
                addToList(line, stringSize, checkedCharacter);
                ++stringSize;
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
            clearErrorPointing(); //Ensure that only own reports will be reported.
            type* line = nullptr;
            unsigned long long stringSize = 0;
            while(!privateEndOfFile)
            {
                type checkedCharacter = getCharacter<type>();
                if(checkedCharacter == '\0')
                {
                    //privateError = errorCode; //Error already tracked.
                    delete[] line;
                    return "";
                }
                addToList(line, stringSize, checkedCharacter);
                ++stringSize;
            }
            addToList(line, stringSize, '\0');
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
            clearErrorPointing(); //Ensure that only own reports will be reported.
            if(privateBinaryMode)
            {
                writeVariable(character);
                if(isError())
                {
                    privateError = extractError();
                    clearErrorPointing();
                    return;
                }
            }
            else
            {
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
            if(!isValidForWriting() or (expectedSize != 0 and !isStringZeroTerminated(string, expectedSize)))
            {
                privateError = errorCode;
                return;
            }
            clearErrorPointing(); //Ensure that only own reports will be reported.
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
            if(!isValidForWriting() or (expectedSize != 0 and !isStringZeroTerminated(string, expectedSize)))
            {
                privateError = errorCode;
                return;
            }
            clearErrorPointing(); //Ensure that only own reports will be reported.
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
            clearErrorPointing(); //Ensure that only own reports will be reported.
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
            clearErrorPointing(); //Ensure that only own reports will be reported.
            int errorCheck = 0;
            switch(from)
            {
                default: privateError = errorCode; return;
                case 1: errorCheck = fseek(file, pointer, SEEK_SET); break;
                case 2: errorCheck = fseek(file, pointer, SEEK_CUR); break;
                case 3: errorCheck = fseek(file, pointer, SEEK_END); break;
                #ifdef _GNU_SOURCE
                case 4: errorCheck = fseek(file, pointer, SEEK_DATA); break;
                case 5: errorCheck = fseek(file, pointer, SEEK_HOLE); break;
                #endif
            }
            
            if(errorCheck != 0 or isError())
            {
                privateError = extractError();
                clearErrorPointing();
                return;
            }
            privateEndOfFile = false;
            updateEndOfFile();
        }

        ///Returns size of a file.
        unsigned long long size(int errorCode = defaultErrorCode)
        {
            if(privateMode == 3 or !isStreamOpen())
            {
                privateError = errorCode;
                return 0;
            }
            clearErrorPointing(); //Ensure that only own reports will be reported.
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
            return returned;
        }

        /**Function which reads in fprintf/fscanf format. Requires pointers to variables, not variables itself.
        *You can specify type for format characters(char, char16_t, char32_t).
        *Syntax is following:
        *fileStreamName.getBtFormat<type>(format, pointers to all variables to which result will be written);
        */
        template<class type, class... Arguments>
        int getByFormat(const type* const format, Arguments*... arguments)
        {
            //if(!isValidForTextReading())
            if(!isValidForReading())
            {
                privateError = defaultErrorCode;
                return 0;
            }
            clearErrorPointing(); //Ensure that only own reports will be reported.
            //If format strings can be influenced by an attacker, they can be exploited (CWE-134). Use a constant for the format specification.
            int processedInt = fscanf(file, format, arguments...);
            if(isError())
            {
                privateError = extractError();
                clearErrorPointing();
                return privateError;
            }
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
            //if(!isValidForTextWriting())
            if(!isValidForWriting())
            {
                privateError = defaultErrorCode;
                return 0;
            }
            clearErrorPointing(); //Ensure that only own reports will be reported.
            //If format strings can be influenced by an attacker, they can be exploited (CWE-134). Use a constant for the format specification.
            int processedInt = fprintf(file, format, arguments...);
            if(isError())
            {
                privateError = extractError();
                clearErrorPointing();
                return privateError;
            }
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
        type* readBlock(const unsigned long long &count, unsigned long long errorCode = defaultErrorCode)
        {
            if(count == 0)
            {
                privateError = ENOTSUP; //How I should allocate zero size array?
                return nullptr;
            }
            if(!isValidForBinaryReading())
            {
                privateError = errorCode;
                return nullptr;
            }
            clearErrorPointing(); //Ensure that only own reports will be reported.
            type* pointer = new type[count];
            unsigned long long result = fread(pointer, sizeof(type), count, file);
            if(isError())
            {
                privateError = extractError();
                clearErrorPointing();
                delete[] pointer;
                return nullptr;
            }
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
        *fileStreamName.readVariable<type of read value>();
        */
        template<class type>
        type readVariable(unsigned long long errorCode = defaultErrorCode)
        {
            if(!isValidForBinaryReading())
            {
                privateError = errorCode;
                return 0;
            }
            clearErrorPointing(); //Ensure that only own reports will be reported.
            type variable;
            unsigned long long result = fread(&variable, sizeof(type), 1, file);
            if(isError())
            {
                privateError = extractError();
                clearErrorPointing();
                return 0;
            }
            updateEndOfFile();
            if(result == 0 or isError())
            {
                privateError = extractError();
                clearErrorPointing();
                return 0;
            }
            return variable;
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
            clearErrorPointing(); //Ensure that only own reports will be reported.
            unsigned long long result = fwrite(pointer, sizeof(type), count, file);
            if(isError())
            {
                privateError = extractError();
                clearErrorPointing();
                return;
            }
            if(result == 0 or result != count)
            {
                privateError = errorCode;
                return;
            }
            if(isError())
            {
                privateError = extractError();
                clearErrorPointing();
                return;
            }
            updateEndOfFile();
        }

        /**Function which reads in binary.
        *Syntax is following:
        *fileStreamName.writeVariable<type of written value, unnecessary>(written element);
        */
        template<class type>
        void writeVariable(const type &variable, unsigned long long errorCode = defaultErrorCode)
        {
            if(!isValidForBinaryWriting())
            {
                privateError = errorCode;
                return;
            }
            clearErrorPointing(); //Ensure that only own reports will be reported.
            unsigned long long result = fwrite(&variable, sizeof(type), 1, file);
            if(isError())
            {
                privateError = extractError();
                clearErrorPointing();
                return;
            }
            if(result != 1)
            {
                privateError = errorCode;
                return;
            }
            if(isError())
            {
                privateError = extractError();
                clearErrorPointing();
                return;
            }
            updateEndOfFile();
        }

        ///Compare two file streams.
        inline bool operator==(const fileStream& file) const
        {
            return (isStringsEqual(file.path, path) and (file.mode == mode) and (file.binary == binary));
        }

        ///Opens new file stream with the same parameters as old.
        template<class type>
        fileStream<type> operator=(const fileStream<type>& file)
        {
            close();
            if(file.path != nullptr and file.mode != 0)
            {
                open(file.path, file.mode, file.binary);
            }
            return *this;
        }
};

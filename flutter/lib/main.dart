import 'package:flutter/material.dart';
import 'package:dotted_border/dotted_border.dart';
import 'package:file_picker/file_picker.dart';
import 'package:http/http.dart' as http;
import 'dart:convert';

void main() => runApp(MyApp());

class MyApp extends StatelessWidget {
  @override
  Widget build(BuildContext context) {
    return MaterialApp(
      title: 'Androml',
      theme: ThemeData(
        primarySwatch: Colors.blue,
      ),
      home: FilePickerScreen(),
    );
  }
}

class FilePickerScreen extends StatefulWidget {
  @override
  _FilePickerScreenState createState() => _FilePickerScreenState();
}

class _FilePickerScreenState extends State<FilePickerScreen> {
  String? _filePath;
  String? _apiResponse;

  Future<void> _openFilePicker() async {
    FilePickerResult? result = await FilePicker.platform.pickFiles();

    if (result != null) {
      setState(() {
        _filePath = result.files.single.path!;
      });
    } else {
    }
  }

  Future<void> _uploadFile() async {
    if (_filePath != null) {
      var request = http.MultipartRequest(
        'POST',
        Uri.parse('http://10.0.2.2:5000/upload_apk'),
      );

      request.files.add(
        await http.MultipartFile.fromPath(
          'file',
          _filePath!,
        ),
      );

      var response = await request.send();
      if (response.statusCode == 200) {
        var responseBody = await response.stream.bytesToString();
        setState(() {
          _apiResponse = responseBody;
        });
        Navigator.push(
          context,
          MaterialPageRoute(builder: (context) => ResultScreen(apiResponse: _apiResponse)),
        );
      } else {
        // API'ye dosya yükleme başarısız oldu
      }
    }
  }

  @override
  Widget build(BuildContext context) {
    return Scaffold(
      appBar: AppBar(
        title: Text('androml'),
      ),
      body: Center(
        child: Column(
          mainAxisAlignment: MainAxisAlignment.center,
          children: <Widget>[
            DottedBorder(
              dashPattern: [6, 3],
              borderType: BorderType.RRect,
              radius: Radius.circular(12),
              strokeWidth: 2,
              child: InkWell(
                onTap: _openFilePicker,
                child: Container(
                  width: 200,
                  height: 200,
                  alignment: Alignment.center,
                  child: _filePath != null
                      ? Icon(Icons.upload_file, size: 60, color: Colors.blue)
                      : Icon(Icons.file_upload, size: 60, color: Colors.blue),
                ),
              ),
            ),
            SizedBox(height: 20),
            _filePath != null
                ? ElevatedButton(
              onPressed: _uploadFile,
              child: Text('Upload File'),
            )
                : Text('Please select a apk file.'),
          ],
        ),
      ),
    );
  }
}

class ResultScreen extends StatelessWidget {
  final String? apiResponse;

  ResultScreen({required this.apiResponse});

  @override
  Widget build(BuildContext context) {
    return Scaffold(
        appBar: AppBar(
        title: Text('API Results'),
    ),
    body: Center(
    child: apiResponse != null
    ? Text(apiResponse!)
        : Text('No result.'),
    ),
    );
  }
}

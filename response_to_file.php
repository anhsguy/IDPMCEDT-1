<?php

function response_to_file($xmlFilePath,$txtFilePath) {
// Load the XML file
// $xmlFilePath = 'getTypelist first valid response 2023-12-24.xml'; // Replace with your XML file path
$xml = simplexml_load_file($xmlFilePath);
function get_element_from_xml($data,$number, $i) {
  $counter = 0;
  foreach ($data->children() as $child) {
      $counter++;
      if ($counter === $number) {
          $name = $child->getName(); // get the name of the 2nd element
          $content = (string) $child; // get the content of the 2nd element
          // echo "Name of the 2nd element: $name\n";
          // $i++;
          echo (string) $i."\t$content\n";
          break; // break the loop after getting the 2nd element
      }
  }
  return $content;
}

if ($xml) {
    // Open a new text file for writing
    // $substring = substr($originalString, 0, -3);
    // $txtFilePath = $substring.'txt'; // Replace with your desired output text file path
    $txtFile = fopen($txtFilePath, 'w');
    $uniqueNames = array();

    if ($txtFile) {
      // Iterate through each element
          $i=0;
          foreach ($xml->children() as $data) {
              // $childCount = count($data);
              // echo "Number of child tags: $childCount\n";
              // echo "Processing data for element: " . $data->getName() . "\n";
              if ($data->getName() === 'response') {
              $description=get_element_from_xml($data,1,$i);
              } else {
                $description=get_element_from_xml($data,2,$i);
              }
              foreach ($data->children() as $child) {
                // echo "Root/data/: {$child->getName()}\n";
                // $childCount = count($child);
                // echo "Number of child tags: $childCount";
                // echo "Data type: ".var_dump($child->getName()[1])."\n";
                $uniqueNames[$child->getName()] = 1;
                if ($child->getName() == 'resourceType') {  
                  $b="{$child}";
                } 
                if ($child->getName() == 'resourceID') {
                  $c="{$child}";
                }
              }
            fwrite($txtFile, (string) $i."\t$description\t\t$b\t\t$c\n");
            $i++;
          }

      // Print the name of the root tag
        
        echo "\nRoot Tag: {$xml->getName()}\t"."{$data->getName()}\n";
        fwrite($txtFile, "\nRoot Tag: {$xml->getName()} > "."{$data->getName()}\n");
        $uniqueNames = array_keys($uniqueNames);
        print_r($uniqueNames);
        if ($uniqueNames[0]=='description'){
          $description=(string)$child;
          echo "Description: $description\n";
        }
        fwrite($txtFile, "\n");
        foreach ($uniqueNames as $name) {
          fwrite($txtFile, $name . PHP_EOL);
      }
        // Close the text file
        fclose($txtFile);

        echo "Extraction successful. Results written to $txtFilePath";
          } else {
              echo "Error opening the text file for writing.";
          }
  } else {
  echo "Error loading the XML file.";
  }
}
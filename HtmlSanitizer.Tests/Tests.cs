using NUnit.Framework;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using CsQuery;

// Tests based on tests from http://roadkill.codeplex.com/

// To create unit tests in this class reference is taken from
// https://www.owasp.org/index.php/XSS_(Cross_Site_Scripting)_Prevention_Cheat_Sheet#RULE_.232_-_Attribute_Escape_Before_Inserting_Untrusted_Data_into_HTML_Common_Attributes
// and http://ha.ckers.org/xss.html

// disable XML comments warnings
#pragma warning disable 1591

namespace Ganss.XSS
{
    /// <summary>
    /// Tests for <see cref="HtmlSanitizer"/>.
    /// </summary>
    [TestFixture]
    [Category("Unit")]
    public class HtmlSanitizerTests
    {
        /// <summary>
        /// A test for Xss locator
        /// </summary>
        [Test]
        public void XSSLocatorTest()
        {
            // Arrange
            var sanitizer = new HtmlSanitizer();

            // Act
            string htmlFragment = "<a href=\"'';!--\"<XSS>=&{()}\">";
            string actual = sanitizer.Sanitize(htmlFragment);

            // Assert
            string expected = @"<a href=""'';!--"">=&amp;{()}&quot;&gt;</a>";
            Assert.That(actual, Is.EqualTo(expected).IgnoreCase);
        }

        /// <summary>
        /// A test for Image Xss vector
        /// Example <!-- <IMG SRC="javascript:alert('XSS');"> -->
        /// </summary>
        [Test]
        public void ImageXSS1Test()
        {
            // Arrange
            var sanitizer = new HtmlSanitizer();


            // Action
            string htmlFragment = "<IMG SRC=\"javascript:alert('XSS');\">";
            string actual = sanitizer.Sanitize(htmlFragment);

            // Assert
            string expected = "<img>";
            Assert.That(actual, Is.EqualTo(expected).IgnoreCase);
        }

        /// <summary>
        /// A test for Image Xss vector without quotes and semicolon.
        /// Example <!-- <IMG SRC=javascript:alert('XSS')> -->
        /// </summary>
        [Test]
        public void ImageXSS2Test()
        {
            // Arrange
            var sanitizer = new HtmlSanitizer();


            // Act
            string htmlFragment = "<IMG SRC=javascript:alert('XSS')>";
            string actual = sanitizer.Sanitize(htmlFragment);

            // Assert
            string expected = "<IMG>";
            Assert.That(actual, Is.EqualTo(expected).IgnoreCase);
        }

        /// <summary>
        /// A test for Image xss vector with case insensitive.
        /// Example <!-- <IMG SRC=JaVaScRiPt:alert('XSS')> -->
        /// </summary>
        [Test]
        public void ImageCaseInsensitiveXSSTest()
        {
            // Arrange
            var sanitizer = new HtmlSanitizer();


            // Act
            string htmlFragment = "<IMG SRC=JaVaScRiPt:alert('XSS')>";
            string actual = sanitizer.Sanitize(htmlFragment);

            // Assert
            string expected = "<IMG>";
            Assert.That(actual, Is.EqualTo(expected).IgnoreCase);
        }

        /// <summary>
        /// A test for Image Xss vector with Html entities
        /// Example <!-- <IMG SRC=javascript:alert(&quot;XSS&quot;)> -->
        /// </summary>
        [Test]
        public void ImageHtmlEntitiesXSSTest()
        {
            // Arrange
            var sanitizer = new HtmlSanitizer();


            // Act
            string htmlFragment = "<IMG SRC=javascript:alert(&quot;XSS&quot;)>";
            string actual = sanitizer.Sanitize(htmlFragment);

            // Assert
            string expected = "<IMG>";
            Assert.That(actual, Is.EqualTo(expected).IgnoreCase);
        }

        /// <summary>
        /// A test for Image Xss vector with grave accent
        /// Example <!-- <IMG SRC=`javascript:alert("RSnake says, 'XSS'")`> -->
        /// </summary>
        [Test]
        public void ImageGraveAccentXSSTest()
        {
            // Arrange
            var sanitizer = new HtmlSanitizer();


            // Act
            string htmlFragment = "<IMG SRC=`javascript:alert(\"RSnake says, 'XSS'\")`>";
            string actual = sanitizer.Sanitize(htmlFragment);

            // Assert
            string expected = "<img>";
            Assert.That(actual, Is.EqualTo(expected).IgnoreCase);
        }

        /// <summary>
        /// A test for Image Xss vector with malformed
        /// Example <!-- <IMG \"\"\"><SCRIPT>alert(\"XSS\")</SCRIPT>\"> -->
        /// </summary>
        [Test]
        public void ImageMalformedXSSTest()
        {
            // Arrange
            var sanitizer = new HtmlSanitizer();


            // Act
            string htmlFragment = "<IMG \"\"\"><SCRIPT>alert(\"XSS\")</SCRIPT>\">";
            string actual = sanitizer.Sanitize(htmlFragment);

            // Assert
            string expected = "<img>&quot;&gt;";
            Assert.That(actual, Is.EqualTo(expected).IgnoreCase);
        }

        /// <summary>
        /// A test for Image Xss vector with ImageFromCharCode
        /// Example <!-- <IMG SRC=javascript:alert(String.fromCharCode(88,83,83))> -->
        /// </summary>
        [Test]
        public void ImageFromCharCodeXSSTest()
        {
            // Arrange
            var sanitizer = new HtmlSanitizer();


            // Act
            string htmlFragment = "<IMG SRC=javascript:alert(String.fromCharCode(88,83,83))>";
            string actual = sanitizer.Sanitize(htmlFragment);

            // Assert
            string expected = "<img>";
            Assert.That(actual, Is.EqualTo(expected).IgnoreCase);
        }

        /// <summary>
        /// A test for Image Xss vector with UTF-8 Unicode
        /// Example <!-- <IMG SRC=&#106;&#97;&#118;&#97;&#115;&#99;&#114;&#105;&#112;&#116;&#58;&#97;&#108;&#101;&#114;&#116;&#40;&#39;&#88;&#83;&#83;&#39;&#41;> -->
        /// </summary>
        [Test]
        public void ImageUTF8UnicodeXSSTest()
        {
            // Arrange
            var sanitizer = new HtmlSanitizer();


            // Act
            string htmlFragment = "<IMG SRC=&#106;&#97;&#118;&#97;&#115;&#99;&#114;&#105;&#112;&#116;&#58;&#97;&#108;&#101;&#114;&#116;&#40;&#39;&#88;&#83;&#83;&#39;&#41;>";
            string actual = sanitizer.Sanitize(htmlFragment);

            // Assert
            string expected = "<img>";
            Assert.That(actual, Is.EqualTo(expected).IgnoreCase);
        }

        /// <summary>
        /// A test for Image Xss vector with Long UTF-8 Unicode
        /// Example <!-- <IMG SRC=&#0000106&#0000097&#0000118&#0000097&#0000115&#0000099&#0000114&#0000105&#0000112&#0000116&#0000058&#0000097&#0000108&#0000101&#0000114&#0000116&#0000040&#0000039&#0000088&#0000083&#0000083&#0000039&#0000041> --> 
        /// </summary>
        [Test]
        public void ImageLongUTF8UnicodeXSSTest()
        {
            // Arrange
            var sanitizer = new HtmlSanitizer();


            // Act
            string htmlFragment = "<IMG SRC=&#0000106&#0000097&#0000118&#0000097&#0000115&#0000099&#0000114&#0000105&#0000112&#0000116&#0000058&#0000097&#0000108&#0000101&#0000114&#0000116&#0000040&#0000039&#0000088&#0000083&#0000083&#0000039&#0000041>";
            string actual = sanitizer.Sanitize(htmlFragment);

            // Assert
            string expected = "<img>";
            Assert.That(actual, Is.EqualTo(expected).IgnoreCase);
        }

        /// <summary>
        /// A test for Image Xss vector with Hex encoding without semicolon
        /// Example <!-- <IMG SRC=&#x6A&#x61&#x76&#x61&#x73&#x63&#x72&#x69&#x70&#x74&#x3A&#x61&#x6C&#x65&#x72&#x74&#x28&#x27&#x58&#x53&#x53&#x27&#x29> -->
        /// </summary>   
        [Test]
        public void ImageHexEncodeXSSTest()
        {
            // Arrange
            var sanitizer = new HtmlSanitizer();


            // Act
            string htmlFragment = "<IMG SRC=&#x6A&#x61&#x76&#x61&#x73&#x63&#x72&#x69&#x70&#x74&#x3A&#x61&#x6C&#x65&#x72&#x74&#x28&#x27&#x58&#x53&#x53&#x27&#x29>";
            string actual = sanitizer.Sanitize(htmlFragment);

            // Assert
            string expected = "<img>";
            Assert.That(actual, Is.EqualTo(expected).IgnoreCase);
        }

        /// <summary>
        /// A test for Image Xss vector with embedded tab
        /// Example <!-- <IMG SRC=\"jav	ascript:alert('XSS');\"> -->
        /// </summary>   
        [Test]
        public void ImageEmbeddedTabXSSTest()
        {
            // Arrange
            var sanitizer = new HtmlSanitizer();


            // Act
            string htmlFragment = "<IMG SRC=\"jav	ascript:alert('XSS');\">";
            string actual = sanitizer.Sanitize(htmlFragment);

            // Assert
            string expected = "<img>";
            Assert.That(actual, Is.EqualTo(expected).IgnoreCase);
        }

        /// <summary>
        /// A test for Image Xss vector with embedded encoded tab
        /// Example <!-- <IMG SRC="jav&#x09;ascript:alert('XSS');"> -->
        /// </summary>   
        [Test]
        public void ImageEmbeddedEncodedTabXSSTest()
        {
            // Arrange
            var sanitizer = new HtmlSanitizer();


            // Act
            string htmlFragment = "<IMG SRC=\"jav&#x09;ascript:alert('XSS');\">";
            string actual = sanitizer.Sanitize(htmlFragment);

            // Assert
            string expected = "<img>";
            Assert.That(actual, Is.EqualTo(expected).IgnoreCase);
        }

        /// <summary>
        /// A test for Image Xss vector with embedded new line
        /// Example <!-- <IMG SRC="jav&#x0A;ascript:alert('XSS');"> -->
        /// </summary>   
        [Test]
        public void ImageEmbeddedNewLineXSSTest()
        {
            // Arrange
            var sanitizer = new HtmlSanitizer();


            // Act
            string htmlFragment = "<IMG SRC=\"jav&#x0A;ascript:alert('XSS');\">";
            string actual = sanitizer.Sanitize(htmlFragment);

            // Assert
            string expected = "<img>";
            Assert.That(actual, Is.EqualTo(expected).IgnoreCase);
        }

        /// <summary>
        /// A test for Image Xss vector with embedded carriage return
        /// Example <!-- <IMG SRC=\"jav&#x0D;ascript:alert('XSS');\"> -->
        /// </summary>   
        [Test]
        public void ImageEmbeddedCarriageReturnXSSTest()
        {
            // Arrange
            var sanitizer = new HtmlSanitizer();


            // Act
            string htmlFragment = "<IMG SRC=\"jav&#x0D;ascript:alert('XSS');\">";
            string actual = sanitizer.Sanitize(htmlFragment);

            // Assert
            string expected = "<img>";
            Assert.That(actual, Is.EqualTo(expected).IgnoreCase);
        }

        /// <summary>
        /// A test for Image Xss vector with Multiline using ASCII carriage return
        /// Example <!-- <IMG
        /// SRC
        /// =
        /// " 
        /// j
        /// a
        /// v
        /// a
        /// s
        /// c
        /// r
        /// i
        /// p
        /// t
        /// :
        /// a
        /// l
        /// e
        /// r
        /// t
        /// (
        /// '
        /// X
        /// S
        /// S
        /// '
        /// )
        /// "
        ///> -->
        /// </summary>   
        [Test]
        public void ImageMultilineInjectedXSSTest()
        {
            // Arrange
            var sanitizer = new HtmlSanitizer();


            // Act
            string htmlFragment = @"<IMG
SRC
=
"" 
j
a
v
a
s
c
r
i
p
t
:
a
l
e
r
t
(
'
X
S
S
'
)
""
>
";

            string actual = sanitizer.Sanitize(htmlFragment);

            // Assert
            string expected = "<img>\n";
            Assert.That(actual, Is.EqualTo(expected).IgnoreCase);
        }

        /// <summary>
        /// A test for Image Xss vector with Null breaks up Javascript directive 
        /// Example <!-- perl -e 'print "<IMG SRC=java\0script:alert(\"XSS\")>";' > out -->
        /// </summary>   
        [Test]
        public void ImageNullBreaksUpXSSTest1()
        {
            // Arrange
            var sanitizer = new HtmlSanitizer();


            // Act
            string htmlFragment = "<IMG SRC=java\0script:alert(\"XSS\")>";
            string actual = sanitizer.Sanitize(htmlFragment);

            // Assert
            string expected = "<img>";
            Assert.That(actual, Is.EqualTo(expected).IgnoreCase);
        }

        /// <summary>
        /// A test for Image Xss vector with Null breaks up cross site scripting vector 
        /// Example <!-- <image src=" perl -e 'print "<SCR\0IPT>alert(\"XSS\")</SCR\0IPT>";' > out "> -->
        /// </summary>
        [Test]
        public void ImageNullBreaksUpXSSTest2()
        {
            // Arrange
            var sanitizer = new HtmlSanitizer();


            // Act
            string htmlFragment = "<SCR\0IPT>alert(\"XSS\")</SCR\0IPT>";
            string actual = sanitizer.Sanitize(htmlFragment);

            // Assert
            string expected = "";
            Assert.That(actual, Is.EqualTo(expected).IgnoreCase);
        }

        /// <summary>
        /// A test for Image Xss vector with spaces and Meta characters 
        /// Example <!-- <IMG SRC=" &#14;  javascript:alert('XSS');"> -->
        /// </summary>
        [Test]
        public void ImageSpaceAndMetaCharXSSTest()
        {
            // Arrange
            var sanitizer = new HtmlSanitizer();


            // Act
            string htmlFragment = "<IMG SRC=\" &#14;  javascript:alert('XSS');\">";
            string actual = sanitizer.Sanitize(htmlFragment);

            // Assert
            string expected = "<img>";
            Assert.That(actual, Is.EqualTo(expected).IgnoreCase);
        }

        /// <summary>
        /// A test for Image Xss vector with half open html
        /// Example <!-- <IMG SRC="javascript:alert('XSS')" -->
        /// </summary>   
        [Test]
        public void ImageHalfOpenHtmlXSSTest()
        {
            // Arrange
            var sanitizer = new HtmlSanitizer();


            // Act
            string htmlFragment = "<IMG SRC=\"javascript:alert('XSS')\"";
            string actual = sanitizer.Sanitize(htmlFragment);

            // Assert
            string expected = "";
            Assert.That(actual, Is.EqualTo(expected).IgnoreCase);
        }

        /// <summary>
        /// A test for Image Xss vector with double open angle bracket
        /// Example <!-- <image src=http://ha.ckers.org/scriptlet.html < -->
        /// </summary>   
        [Test]
        public void ImageDoubleOpenAngleBracketXSSTest()
        {
            // Arrange
            var sanitizer = new HtmlSanitizer();


            // Act
            string htmlFragment = "<image src=http://ha.ckers.org/scriptlet.html <";
            string actual = sanitizer.Sanitize(htmlFragment);

            // Assert
            string expected = "";
            Assert.That(actual, Is.EqualTo(expected).IgnoreCase);
        }

        /// <summary>
        /// A test for Dic Xss vector with Javascript escaping
        /// Example <!-- <div style="\";alert('XSS');//"> -->
        /// </summary>   
        [Test]
        public void DivJavascriptEscapingXSSTest()
        {
            // Arrange
            var sanitizer = new HtmlSanitizer();


            // Act
            string htmlFragment = "<div style=\"\";alert('XSS');//\">";
            string actual = sanitizer.Sanitize(htmlFragment);

            // Assert
            string expected = "<div></div>";
            Assert.That(actual, Is.EqualTo(expected).IgnoreCase);
        }

        /// <summary>
        /// A test for Image Xss vector with input image
        /// Example <!-- <INPUT TYPE="IMAGE" SRC="javascript:alert('XSS');"> -->
        /// </summary>   
        [Test]
        public void ImageInputXSSTest()
        {
            // Arrange
            var sanitizer = new HtmlSanitizer();


            // Act
            string htmlFragment = "<INPUT TYPE=\"IMAGE\" SRC=\"javascript:alert('XSS');\">";
            string actual = sanitizer.Sanitize(htmlFragment);

            // Assert
            string expected = "<input type=\"image\">";
            Assert.That(actual, Is.EqualTo(expected).IgnoreCase);
        }

        /// <summary>
        /// A test for Image Xss vector with Dynsrc
        /// Example <!-- <IMG DYNSRC="javascript:alert('XSS')"> -->
        /// </summary>   
        [Test]
        public void ImageDynsrcXSSTest()
        {
            // Arrange
            var sanitizer = new HtmlSanitizer();


            // Act
            string htmlFragment = "<IMG DYNSRC=\"javascript:alert('XSS')\">";
            string actual = sanitizer.Sanitize(htmlFragment);

            // Assert
            string expected = "<img>";
            Assert.That(actual, Is.EqualTo(expected).IgnoreCase);
        }

        /// <summary>
        /// A test for Image Xss vector with Lowsrc
        /// Example <!-- <IMG LOWSRC="javascript:alert('XSS')"> -->
        /// </summary>   
        [Test]
        public void ImageLowsrcXSSTest()
        {
            // Arrange
            var sanitizer = new HtmlSanitizer();


            // Act
            string htmlFragment = "<IMG LOWSRC=\"javascript:alert('XSS')\">";
            string actual = sanitizer.Sanitize(htmlFragment);

            // Assert
            string expected = "<img>";
            Assert.That(actual, Is.EqualTo(expected).IgnoreCase);
        }

        /// <summary>
        /// A test for Xss vector with BGSound
        /// Example <!-- <BGSOUND SRC="javascript:alert('XSS');"> -->
        /// </summary>   
        [Test]
        public void BGSoundXSSTest()
        {
            // Arrange
            var sanitizer = new HtmlSanitizer();


            // Act
            string htmlFragment = "<BGSOUND SRC=\"javascript:alert('XSS');\">";
            string actual = sanitizer.Sanitize(htmlFragment);

            // Assert
            string expected = "";
            Assert.That(actual, Is.EqualTo(expected).IgnoreCase);
        }

        /// <summary>
        /// A test for BR with Javascript Include
        /// Example <!-- <BR SIZE="&{alert('XSS')}"> -->
        /// </summary>   
        [Test]
        public void BRJavascriptIncludeXSSTest()
        {
            // Arrange
            var sanitizer = new HtmlSanitizer();


            // Act
            string htmlFragment = "<BR SIZE=\"&{alert('XSS')}\">";
            string actual = sanitizer.Sanitize(htmlFragment);

            // Assert
            string expected = "<BR>";
            Assert.That(actual, Is.EqualTo(expected).IgnoreCase);
        }

        /// <summary>
        /// A test for P with url in style
        /// Example <!-- <p STYLE="behavior: url(www.ha.ckers.org);"> -->
        /// </summary>   
        [Test]
        public void PWithUrlInStyleXSSTest()
        {
            // Arrange
            var sanitizer = new HtmlSanitizer();


            // Act
            string htmlFragment = "<p STYLE=\"behavior: url(www.ha.ckers.org);\">";
            string actual = sanitizer.Sanitize(htmlFragment);

            // Assert
            // intentionally keep it failing to get notice when reviewing unit tests so can disucss
            string expected = "<p></p>";
            Assert.That(actual, Is.EqualTo(expected).IgnoreCase);
        }

        /// <summary>
        /// A test for Image with vbscript
        /// Example <!-- <IMG SRC='vbscript:msgbox("XSS")'> -->
        /// </summary>   
        [Test]
        public void ImageWithVBScriptXSSTest()
        {
            // Arrange
            var sanitizer = new HtmlSanitizer();


            // Act
            string htmlFragment = "<IMG SRC='vbscript:msgbox(\"XSS\")'>";
            string actual = sanitizer.Sanitize(htmlFragment);

            // Assert
            string expected = "<img>";
            Assert.That(actual, Is.EqualTo(expected).IgnoreCase);
        }

        /// <summary>
        /// A test for Image with Mocha
        /// Example <!-- <IMG SRC="mocha:[code]"> -->
        /// </summary>   
        [Test]
        public void ImageWithMochaXSSTest()
        {
            // Arrange
            var sanitizer = new HtmlSanitizer();


            // Act
            string htmlFragment = "<IMG SRC=\"mocha:[code]\">";
            string actual = sanitizer.Sanitize(htmlFragment);

            // Assert
            string expected = "<img>";
            Assert.That(actual, Is.EqualTo(expected).IgnoreCase);
        }

        /// <summary>
        /// A test for Image with Livescript
        /// Example <!-- <IMG SRC="Livescript:[code]"> -->
        /// </summary>   
        [Test]
        public void ImageWithLivescriptXSSTest()
        {
            // Arrange
            var sanitizer = new HtmlSanitizer();


            // Act
            string htmlFragment = "<IMG SRC=\"Livescript:[code]\">";
            string actual = sanitizer.Sanitize(htmlFragment);

            // Assert
            string expected = "<img>";
            Assert.That(actual, Is.EqualTo(expected).IgnoreCase);
        }

        /// <summary>
        /// A test for Iframe
        /// Example <!-- <IFRAME SRC="javascript:alert('XSS');"></IFRAME> -->
        /// </summary>   
        [Test]
        public void IframeXSSTest()
        {
            // Arrange
            var sanitizer = new HtmlSanitizer();


            // Act
            string htmlFragment = "<IFRAME SRC=\"javascript:alert('XSS');\"></IFRAME>";
            string actual = sanitizer.Sanitize(htmlFragment);

            // Assert
            string expected = "";
            Assert.That(actual, Is.EqualTo(expected).IgnoreCase);
        }

        /// <summary>
        /// A test for Frame
        /// Example <!-- <FRAMESET><FRAME SRC="javascript:alert('XSS');"></FRAMESET> -->
        /// </summary>   
        [Test]
        public void FrameXSSTest()
        {
            // Arrange
            var sanitizer = new HtmlSanitizer();


            // Act
            string htmlFragment = "<FRAMESET><FRAME SRC=\"javascript:alert('XSS');\"></FRAMESET>";
            string actual = sanitizer.Sanitize(htmlFragment);

            // Assert
            string expected = "";
            Assert.That(actual, Is.EqualTo(expected).IgnoreCase);
        }

        /// <summary>
        /// A test for Table
        /// Example <!-- <TABLE BACKGROUND="javascript:alert('XSS')"> -->
        /// </summary>   
        [Test]
        public void TableXSSTest()
        {
            // Arrange
            var sanitizer = new HtmlSanitizer();


            // Act
            string htmlFragment = "<TABLE BACKGROUND=\"javascript:alert('XSS')\">";
            string actual = sanitizer.Sanitize(htmlFragment);

            // Assert
            string expected = "<table></table>";
            Assert.That(actual, Is.EqualTo(expected).IgnoreCase);
        }

        /// <summary>
        /// A test for TD
        /// Example <!-- <TABLE><TD BACKGROUND="javascript:alert('XSS')"> -->
        /// </summary>   
        [Test]
        public void TDXSSTest()
        {
            // Arrange
            var sanitizer = new HtmlSanitizer();


            // Act
            string htmlFragment = "<TABLE><TD BACKGROUND=\"javascript:alert('XSS')\">";
            string actual = sanitizer.Sanitize(htmlFragment);

            // Assert
            string expected = "<table><tbody><tr><td></td></tr></tbody></table>";
            Assert.That(actual, Is.EqualTo(expected).IgnoreCase);
        }

        /// <summary>
        /// A test for Div Background Image
        /// Example <!-- <DIV STYLE="background-image: url(javascript:alert('XSS'))"> -->
        /// </summary>   
        [Test]
        public void DivBackgroundImageXSSTest()
        {
            // Arrange
            var sanitizer = new HtmlSanitizer();


            // Act
            string htmlFragment = "<DIV STYLE=\"background-image: url(javascript:alert('XSS'))\">";
            string actual = sanitizer.Sanitize(htmlFragment);

            // Assert
            string expected = "<div></div>";
            Assert.That(actual, Is.EqualTo(expected).IgnoreCase);
        }

        /// <summary>
        /// A test for Div Background Image  with unicoded XSS
        /// Example <!-- <DIV STYLE="background-image:\0075\0072\006C\0028'\006a\0061\0076\0061\0073\0063\0072\0069\0070\0074\003a\0061\006c\0065\0072\0074\0028.1027\0058.1053\0053\0027\0029'\0029"> -->
        /// </summary>   
        [Test]
        public void DivBackgroundImageWithUnicodedXSSTest()
        {
            // Arrange
            var sanitizer = new HtmlSanitizer();


            // Act
            string htmlFragment = @"<DIV STYLE=""background-image:\0075\0072\006C\0028'\006a\0061\0076\0061\0073\0063\0072\0069\0070\0074\003a\0061\006c\0065\0072\0074\0028\0027\0058\0053\0053\0027\0029'\0029"">";
            string actual = sanitizer.Sanitize(htmlFragment);

            // Assert
            string expected = "<div></div>";
            Assert.That(actual, Is.EqualTo(expected).IgnoreCase);
        }

        /// <summary>
        /// A test for Div Background Image  with extra characters
        /// Example <!-- <DIV STYLE="background-image: url(&#1;javascript:alert('XSS'))"> -->
        /// </summary>   
        [Test]
        public void DivBackgroundImageWithExtraCharactersXSSTest()
        {
            // Arrange
            var sanitizer = new HtmlSanitizer();


            // Act
            string htmlFragment = "<DIV STYLE=\"background-image: url(&#1;javascript:alert('XSS'))\">";
            string actual = sanitizer.Sanitize(htmlFragment);

            // Assert
            string expected = "<div></div>";
            Assert.That(actual, Is.EqualTo(expected).IgnoreCase);
        }

        /// <summary>
        /// A test for DIV expression
        /// Example <!-- <DIV STYLE="width: expression(alert('XSS'));"> -->
        /// </summary>   
        [Test]
        public void DivExpressionXSSTest()
        {
            // Arrange
            var sanitizer = new HtmlSanitizer();


            // Act
            string htmlFragment = "<DIV STYLE=\"width: expression(alert('XSS'));\">";
            string actual = sanitizer.Sanitize(htmlFragment);

            // Assert
            string expected = "<div></div>";
            Assert.That(actual, Is.EqualTo(expected).IgnoreCase);
        }

        /// <summary>
        /// A test for Image with break up expression
        /// Example <!-- <IMG STYLE="xss:expr/*XSS*/ession(alert('XSS'))"> -->
        /// </summary>   
        [Test]
        public void ImageStyleExpressionXSSTest()
        {
            // Arrange
            var sanitizer = new HtmlSanitizer();


            // Act
            string htmlFragment = "<IMG STYLE=\"xss:expr/*XSS*/ession(alert('XSS'))\">";
            string actual = sanitizer.Sanitize(htmlFragment);

            // Assert
            string expected = "<IMG>";
            Assert.That(actual, Is.EqualTo(expected).IgnoreCase);
        }

        /// <summary>
        /// A test for AnchorTag with break up expression
        /// Example <!-- exp/*<A STYLE='no\xss:noxss("*//*");xss:&#101;x&#x2F;*XSS*//*/*/pression(alert("XSS"))'> -->
        /// </summary>   
        [Test]
        public void AnchorTagStyleExpressionXSSTest()
        {
            // Arrange
            var sanitizer = new HtmlSanitizer();


            // Act
            string htmlFragment = "exp/*<A STYLE='no\\xss:noxss(\"*//*\");xss:&#101;x&#x2F;*XSS*//*/*/pression(alert(\"XSS\"))'>";
            string actual = sanitizer.Sanitize(htmlFragment);

            // Assert
            string expected = "exp/*<a></a>";
            Assert.That(actual, Is.EqualTo(expected).IgnoreCase);
        }

        /// <summary>
        /// A test for BaseTag
        /// Example <!-- <BASE HREF="javascript:alert('XSS');//"> -->
        /// </summary>   
        [Test]
        public void BaseTagXSSTest()
        {
            // Arrange
            var sanitizer = new HtmlSanitizer();


            // Act
            string htmlFragment = "<BASE HREF=\"javascript:alert('XSS');//\">";
            string actual = sanitizer.Sanitize(htmlFragment);

            // Assert
            string expected = "";
            Assert.That(actual, Is.EqualTo(expected).IgnoreCase);
        }

        /// <summary>
        /// A test for EMBEDTag
        /// Example <!-- <EMBED SRC="http://ha.ckers.org/xss.swf" AllowScriptAccess="always"></EMBED> -->
        /// </summary>   
        [Test]
        public void EmbedTagXSSTest()
        {
            // Arrange
            var sanitizer = new HtmlSanitizer();


            // Act
            string htmlFragment = "<EMBED SRC=\"http://ha.ckers.org/xss.swf\" AllowScriptAccess=\"always\"></EMBED>";
            string actual = sanitizer.Sanitize(htmlFragment);

            // Assert
            string expected = "";
            Assert.That(actual, Is.EqualTo(expected).IgnoreCase);
        }

        /// <summary>
        /// A test for EMBEDSVG
        /// Example <!-- <EMBED SRC="data:image/svg+xml;base64,PHN2ZyB4bWxuczpzdmc9Imh0dH A6Ly93d3cudzMub3JnLzIwMDAvc3ZnIiB4bWxucz0iaHR0cDovL3d3dy53My5vcmcv MjAwMC9zdmciIHhtbG5zOnhsaW5rPSJodHRwOi8vd3d3LnczLm9yZy8xOTk5L3hs aW5rIiB2ZXJzaW9uPSIxLjAiIHg9IjAiIHk9IjAiIHdpZHRoPSIxOTQiIGhlaWdodD0iMjAw IiBpZD0ieHNzIj48c2NyaXB0IHR5cGU9InRleHQvZWNtYXNjcmlwdCI+YWxlcnQoIlh TUyIpOzwvc2NyaXB0Pjwvc3ZnPg==" type="image/svg+xml" AllowScriptAccess="always"></EMBED> -->
        /// </summary>   
        [Test]
        public void EmbedSVGXSSTest()
        {
            // Arrange
            var sanitizer = new HtmlSanitizer();


            // Act
            string htmlFragment = "<EMBED SRC=\"data:image/svg+xml;base64,PHN2ZyB4bWxuczpzdmc9Imh0dH A6Ly93d3cudzMub3JnLzIwMDAvc3ZnIiB4bWxucz0iaHR0cDovL3d3dy53My5vcmcv MjAwMC9zdmciIHhtbG5zOnhsaW5rPSJodHRwOi8vd3d3LnczLm9yZy8xOTk5L3hs aW5rIiB2ZXJzaW9uPSIxLjAiIHg9IjAiIHk9IjAiIHdpZHRoPSIxOTQiIGhlaWdodD0iMjAw IiBpZD0ieHNzIj48c2NyaXB0IHR5cGU9InRleHQvZWNtYXNjcmlwdCI+YWxlcnQoIlh TUyIpOzwvc2NyaXB0Pjwvc3ZnPg==\" type=\"image/svg+xml\" AllowScriptAccess=\"always\"></EMBED>";
            string actual = sanitizer.Sanitize(htmlFragment);

            // Assert
            string expected = "";
            Assert.That(actual, Is.EqualTo(expected).IgnoreCase);
        }

        /// <summary>
        /// A test for XML namespace
        /// Example <!-- <HTML xmlns:xss>  <?import namespace="xss" implementation="http://ha.ckers.org/xss.htc">  <xss:xss>XSS</xss:xss></HTML> -->
        /// </summary>   
        [Test]
        public void XmlNamespaceXSSTest()
        {
            // Arrange
            var sanitizer = new HtmlSanitizer();


            // Act
            string htmlFragment = "<HTML xmlns:xss>  <?import namespace=\"xss\" implementation=\"http://ha.ckers.org/xss.htc\">  <xss:xss>XSS</xss:xss></HTML>";
            string actual = sanitizer.Sanitize(htmlFragment);

            // Assert
            string expected = "";
            Assert.That(actual, Is.EqualTo(expected).IgnoreCase);
        }

        /// <summary>
        /// A test for XML with CData
        /// Example <!-- <XML ID=I><X><C><![CDATA[<IMG SRC="javas]]><![CDATA[cript:alert('XSS');">]]></C></X></xml><SPAN DATASRC=#I DATAFLD=C DATAFORMATAS=HTML></SPAN> -->
        /// </summary>   
        [Test]
        public void XmlWithCDataXSSTest()
        {
            // Arrange
            var sanitizer = new HtmlSanitizer();


            // Act
            string htmlFragment = "<XML ID=I><X><C><![CDATA[<IMG SRC=\"javas]]><![CDATA[cript:alert('XSS');\">]]></C></X></xml><SPAN DATASRC=#I DATAFLD=C DATAFORMATAS=HTML></SPAN>";
            string actual = sanitizer.Sanitize(htmlFragment);

            // Assert
            string expected = "<SPAN></SPAN>";
            Assert.That(actual, Is.EqualTo(expected).IgnoreCase);
        }

        /// <summary>
        /// A test for XML with Comment obfuscation
        /// </summary>   
        [Test]
        public void XmlWithCommentObfuscationXSSTest()
        {
            // Arrange
            var sanitizer = new HtmlSanitizer();


            // Act
            string htmlFragment = "<XML ID=\"xss\"><I><B>&lt;IMG SRC=\"javas<!-- -->cript:alert('XSS')\"&gt;</B></I></XML><SPAN DATASRC=\"#xss\" DATAFLD=\"B\" DATAFORMATAS=\"HTML\"></SPAN>";
            string actual = sanitizer.Sanitize(htmlFragment);

            // Assert
            string expected = "<SPAN></SPAN>";
            Assert.That(actual, Is.EqualTo(expected).IgnoreCase);
        }

        /// <summary>
        /// A test for XML with Embedded script
        /// Example <!-- <XML SRC="xsstest.xml" ID=I></XML><SPAN DATASRC=#I DATAFLD=C DATAFORMATAS=HTML></SPAN> -->
        /// </summary>   
        [Test]
        public void XmlWithEmbeddedScriptXSSTest()
        {
            // Arrange
            var sanitizer = new HtmlSanitizer();


            // Act
            string htmlFragment = "<XML SRC=\"xsstest.xml\" ID=I></XML><SPAN DATASRC=#I DATAFLD=C DATAFORMATAS=HTML></SPAN>";
            string actual = sanitizer.Sanitize(htmlFragment);

            // Assert
            string expected = "<SPAN></SPAN>";
            Assert.That(actual, Is.EqualTo(expected).IgnoreCase);
        }

        /// <summary>
        /// A test for Html + Time
        /// Example <!-- <HTML><BODY><?xml:namespace prefix="t" ns="urn:schemas-microsoft-com:time"><?import namespace="t" implementation="#default#time2"><t:set attributeName="innerHTML" to="XSS&lt;SCRIPT DEFER&gt;alert(&quot;XSS&quot;)&lt;/SCRIPT&gt;"></BODY></HTML> -->
        /// </summary>   
        [Test]
        public void HtmlPlusTimeXSSTest()
        {
            // Arrange
            var sanitizer = new HtmlSanitizer();


            // Act
            string htmlFragment = "<HTML><BODY><?xml:namespace prefix=\"t\" ns=\"urn:schemas-microsoft-com:time\"><?import namespace=\"t\" implementation=\"#default#time2\"><t:set attributeName=\"innerHTML\" to=\"XSS&lt;SCRIPT DEFER&gt;alert(&quot;XSS&quot;)&lt;/SCRIPT&gt;\"></BODY></HTML>";
            string actual = sanitizer.Sanitize(htmlFragment);

            // Assert
            string expected = "";
            Assert.That(actual, Is.EqualTo(expected).IgnoreCase);
        }

        /// <summary>
        /// A test for AnchorTag with javascript link location
        /// Example <!-- <A HREF="javascript:document.location='http://www.google.com/'">XSS</A> -->
        /// </summary>   
        [Test]
        public void AnchorTagJavascriptLinkLocationXSSTest()
        {
            // Arrange
            var sanitizer = new HtmlSanitizer();


            // Act
            string htmlFragment = "<A HREF=\"javascript:document.location='http://www.google.com/'\">XSS</A>";
            string actual = sanitizer.Sanitize(htmlFragment);

            // Assert
            string expected = "<a>XSS</a>";
            Assert.That(actual, Is.EqualTo(expected).IgnoreCase);
        }

        /// <summary>
        /// A test for Div with no filter evasion
        /// Example <!-- <Div style="background-color: http://www.codeplex.com?url=<SCRIPT SRC=http://ha.ckers.org/xss.js></SCRIPT>"> -->
        /// </summary>   
        [Test]
        public void DivNoFilterEvasionXSSTest()
        {
            // Arrange
            var sanitizer = new HtmlSanitizer();


            // Act
            string htmlFragment = "<Div style=\"background-color: http://www.codeplex.com?url=<SCRIPT SRC=http://ha.ckers.org/xss.js></SCRIPT>\">";
            string actual = sanitizer.Sanitize(htmlFragment);

            // Assert
            string expected = "<div></div>";
            Assert.That(actual, Is.EqualTo(expected).IgnoreCase);
        }

        /// <summary>
        /// A test for Div with style expression and no filter evasion
        /// Example <!-- <Div style="background-color: expression(<SCRIPT SRC=http://ha.ckers.org/xss.js></SCRIPT>)"> -->
        /// </summary>   
        [Test]
        public void DivStyleExpressionNoFilterEvasionXSSTest()
        {
            // Arrange
            var sanitizer = new HtmlSanitizer();


            // Act
            string htmlFragment = "<Div style=\"background-color: expression(<SCRIPT SRC=http://ha.ckers.org/xss.js></SCRIPT>)\">";
            string actual = sanitizer.Sanitize(htmlFragment);

            // Assert
            string expected = "<div></div>";
            Assert.That(actual, Is.EqualTo(expected).IgnoreCase);
        }

        /// <summary>
        /// A test for AnchorTag with non alpha non digit xss
        /// Example <!-- <A HREF="http://www.codeplex.com?url=<SCRIPT/XSS SRC="http://ha.ckers.org/xss.js"></SCRIPT>">XSS</A> -->
        /// </summary>   
        [Test]
        public void AnchorTagNonAlphaNonDigitXSSTest()
        {
            // Arrange
            var sanitizer = new HtmlSanitizer();


            // Act
            string htmlFragment = "<A HREF=\"http://www.codeplex.com?url=<SCRIPT/XSS SRC=\"http://ha.ckers.org/xss.js\"></SCRIPT>\">XSS</A>";
            string actual = sanitizer.Sanitize(htmlFragment);

            // Assert
            string expected = "<a>&quot;&gt;XSS</a>";
            Assert.That(actual, Is.EqualTo(expected).IgnoreCase);
        }

        /// <summary>
        /// A test for Div with non alpha non digit xss
        /// Example <!-- <Div style="background-color: http://www.codeplex.com?url=<SCRIPT/XSS SRC=http://ha.ckers.org/xss.js></SCRIPT>"> -->
        /// </summary>   
        [Test]
        public void DivNonAlphaNonDigitXSSTest()
        {
            // Arrange
            var sanitizer = new HtmlSanitizer();


            // Act
            string htmlFragment = "<Div style=\"background-color: http://www.codeplex.com?url=<SCRIPT/XSS SRC=\"http://ha.ckers.org/xss.js\"></SCRIPT>\">";
            string actual = sanitizer.Sanitize(htmlFragment);

            // Assert
            string expected = "<div>&quot;&gt;</div>";
            Assert.That(actual, Is.EqualTo(expected).IgnoreCase);
        }

        /// <summary>
        /// A test for Div with style expression and non alpha non digit xss
        /// Example <!-- <Div style="background-color: expression(<SCRIPT/XSS SRC="http://ha.ckers.org/xss.js"></SCRIPT>)"> -->
        /// </summary>   
        [Test]
        public void DivStyleExpressionNonAlphaNonDigitXSSTest()
        {
            // Arrange
            var sanitizer = new HtmlSanitizer();


            // Act
            string htmlFragment = "<Div style=\"background-color: expression(<SCRIPT/XSS SRC=\"http://ha.ckers.org/xss.js\"></SCRIPT>)\">";
            string actual = sanitizer.Sanitize(htmlFragment);

            // Assert
            string expected = "<div>)&quot;&gt;</div>";
            Assert.That(actual, Is.EqualTo(expected).IgnoreCase);
        }

        /// <summary>
        /// A test for Div with non alpha non digit part 3 xss
        /// Example <!-- <Div style="background-color: http://www.codeplex.com?url=<SCRIPT/SRC=http://ha.ckers.org/xss.js></SCRIPT>"> -->
        /// </summary>   
        [Test]
        public void DivNonAlphaNonDigit3XSSTest()
        {
            // Arrange
            var sanitizer = new HtmlSanitizer();


            // Act
            string htmlFragment = "<Div style=\"background-color: http://www.codeplex.com?url=<SCRIPT/SRC=\"http://ha.ckers.org/xss.js\"></SCRIPT>\">";
            string actual = sanitizer.Sanitize(htmlFragment);

            // Assert
            string expected = "<div>&quot;&gt;</div>";
            Assert.That(actual, Is.EqualTo(expected).IgnoreCase);
        }

        /// <summary>
        /// A test for Div with style expression and non alpha non digit part 3 xss
        /// Example <!-- <Div style="background-color: expression(<SCRIPT/SRC="http://ha.ckers.org/xss.js"></SCRIPT>)"> -->
        /// </summary>   
        [Test]
        public void DivStyleExpressionNonAlphaNonDigit3XSSTest()
        {
            // Arrange
            var sanitizer = new HtmlSanitizer();


            // Act
            string htmlFragment = "<Div style=\"background-color: expression(<SCRIPT/SRC=\"http://ha.ckers.org/xss.js\"></SCRIPT>)\">";
            string actual = sanitizer.Sanitize(htmlFragment);

            // Assert
            string expected = "<div>)&quot;&gt;</div>";
            Assert.That(actual, Is.EqualTo(expected).IgnoreCase);
        }

        /// <summary>
        /// A test for AnchorTag with Extraneous open brackets xss
        /// Example <!-- <A HREF="http://www.codeplex.com?url=<<SCRIPT>alert("XSS");//<</SCRIPT>">XSS</A> -->
        /// </summary>   
        [Test]
        public void AnchorTagExtraneousOpenBracketsXSSTest()
        {
            // Arrange
            var sanitizer = new HtmlSanitizer();


            // Act
            string htmlFragment = "<A HREF=\"http://www.codeplex.com?url=<<SCRIPT>alert(\"XSS\");//<</SCRIPT>\">XSS</A>";
            string actual = sanitizer.Sanitize(htmlFragment);

            // Assert
            string expected = "<a>&quot;&gt;XSS</a>";
            Assert.That(actual, Is.EqualTo(expected).IgnoreCase);
        }

        /// <summary>
        /// A test for Div with Extraneous open brackets xss
        /// Example <!-- <Div style="background-color: http://www.codeplex.com?url=<<SCRIPT>alert("XSS");//<</SCRIPT>"> -->
        /// </summary>   
        [Test]
        public void DivExtraneousOpenBracketsXSSTest()
        {
            // Arrange
            var sanitizer = new HtmlSanitizer();


            // Act
            string htmlFragment = "<Div style=\"background-color: http://www.codeplex.com?url=<<SCRIPT>alert(\"XSS\");//<</SCRIPT>\">";
            string actual = sanitizer.Sanitize(htmlFragment);

            // Assert
            string expected = "<div>&quot;&gt;</div>";
            Assert.That(actual, Is.EqualTo(expected).IgnoreCase);
        }

        /// <summary>
        /// A test for Div with style expression and Extraneous open brackets xss
        /// Example <!-- <Div style="background-color: expression(<<SCRIPT>alert("XSS");//<</SCRIPT>)"> -->
        /// </summary>   
        [Test]
        public void DivStyleExpressionExtraneousOpenBracketsXSSTest()
        {
            // Arrange
            var sanitizer = new HtmlSanitizer();


            // Act
            string htmlFragment = "<Div style=\"background-color: expression(<<SCRIPT>alert(\"XSS\");//<</SCRIPT>)\">";
            string actual = sanitizer.Sanitize(htmlFragment);

            // Assert
            string expected = "<div>)&quot;&gt;</div>";
            Assert.That(actual, Is.EqualTo(expected).IgnoreCase);
        }

        /// <summary>
        /// A test for Div with No closing script tags xss
        /// Example <!-- <Div style="background-color: http://www.codeplex.com?url=<SCRIPT SRC=http://ha.ckers.org/xss.js?<B>"> -->
        /// </summary>   
        [Test]
        public void DivNoClosingScriptTagsXSSTest()
        {
            // Arrange
            var sanitizer = new HtmlSanitizer();


            // Act
            string htmlFragment = "<Div style=\"background-color: http://www.codeplex.com?url=<SCRIPT SRC=http://ha.ckers.org/xss.js?<B>\">";
            string actual = sanitizer.Sanitize(htmlFragment);

            // Assert
            string expected = "<div></div>";
            Assert.That(actual, Is.EqualTo(expected).IgnoreCase);
        }

        /// <summary>
        /// A test for Div with style expression and No closing script tags xss
        /// Example <!-- <Div style="background-color: expression(<SCRIPT SRC=http://ha.ckers.org/xss.js?<B>)"> -->
        /// </summary>   
        [Test]
        public void DivStyleExpressionNoClosingScriptTagsXSSTest()
        {
            // Arrange
            var sanitizer = new HtmlSanitizer();


            // Act
            string htmlFragment = "<Div style=\"background-color: expression(<SCRIPT SRC=http://ha.ckers.org/xss.js?<B>)\">";
            string actual = sanitizer.Sanitize(htmlFragment);

            // Assert
            string expected = "<div></div>";
            Assert.That(actual, Is.EqualTo(expected).IgnoreCase);
        }

        /// <summary>
        /// A test for AnchorTag with Protocol resolution in script tags xss
        /// Example <!-- <A HREF="http://www.codeplex.com?url=<SCRIPT SRC=//ha.ckers.org/.j>">XSS</A> -->
        /// </summary>   
        [Test]
        public void AnchorTagProtocolResolutionScriptXSSTest()
        {
            // Arrange
            var sanitizer = new HtmlSanitizer();


            // Act
            string htmlFragment = "<A HREF=\"http://www.codeplex.com?url=<SCRIPT SRC=//ha.ckers.org/.j>\">XSS</A>";
            string actual = sanitizer.Sanitize(htmlFragment);

            // Assert
            string expected = "<a>XSS</a>";
            Assert.That(actual, Is.EqualTo(expected).IgnoreCase);
        }

        /// <summary>
        /// A test for Div with Protocol resolution in script tags xss
        /// Example <!-- <Div style="background-color: http://www.codeplex.com?url=<SCRIPT SRC=//ha.ckers.org/.j>"> -->
        /// </summary>   
        [Test]
        public void DivProtocolResolutionScriptXSSTest()
        {
            // Arrange
            var sanitizer = new HtmlSanitizer();


            // Act
            string htmlFragment = "<Div style=\"background-color: http://www.codeplex.com?url=<SCRIPT SRC=//ha.ckers.org/.j>\">";
            string actual = sanitizer.Sanitize(htmlFragment);

            // Assert
            string expected = "<div></div>";
            Assert.That(actual, Is.EqualTo(expected).IgnoreCase);
        }

        /// <summary>
        /// A test for Div with style expression and Protocol resolution in script tags xss
        /// Example <!-- <Div style="background-color: expression(<SCRIPT SRC=//ha.ckers.org/.j>)"> -->
        /// </summary>   
        [Test]
        public void DivStyleExpressionProtocolResolutionScriptXSSTest()
        {
            // Arrange
            var sanitizer = new HtmlSanitizer();


            // Act
            string htmlFragment = "<Div style=\"background-color: expression(<SCRIPT SRC=//ha.ckers.org/.j>)\">";
            string actual = sanitizer.Sanitize(htmlFragment);

            // Assert
            string expected = "<div></div>";
            Assert.That(actual, Is.EqualTo(expected).IgnoreCase);
        }

        /// <summary>
        /// A test for AnchorTag with no single quotes or double quotes or semicolons xss
        /// Example <!-- <A HREF="http://www.codeplex.com?url=<SCRIPT>a=/XSS/alert(a.source)</SCRIPT>">XSS</A> -->
        /// </summary>   
        [Test]
        public void AnchorTagNoQuotesXSSTest()
        {
            // Arrange
            var sanitizer = new HtmlSanitizer();


            // Act
            string htmlFragment = "<A HREF=\"http://www.codeplex.com?url=<SCRIPT>a=/XSS/alert(a.source)</SCRIPT>\">XSS</A>";
            string actual = sanitizer.Sanitize(htmlFragment);

            // Assert
            string expected = "<a>XSS</a>";
            Assert.That(actual, Is.EqualTo(expected).IgnoreCase);
        }

        /// <summary>
        /// A test for Div with no single quotes or double quotes or semicolons xss
        /// Example <!-- <Div style="background-color: http://www.codeplex.com?url=<SCRIPT>a=/XSS/alert(a.source)</SCRIPT>"> -->
        /// </summary>   
        [Test]
        public void DivNoQuotesXSSTest()
        {
            // Arrange
            var sanitizer = new HtmlSanitizer();


            // Act
            string htmlFragment = "<Div style=\"background-color: http://www.codeplex.com?url=<SCRIPT>a=/XSS/alert(a.source)</SCRIPT>\">";
            string actual = sanitizer.Sanitize(htmlFragment);

            // Assert
            string expected = "<div></div>";
            Assert.That(actual, Is.EqualTo(expected).IgnoreCase);
        }

        /// <summary>
        /// A test for Div with style expression and no single quotes or double quotes or semicolons xss
        /// Example <!-- <Div style="background-color: expression(<SCRIPT>a=/XSS/alert(a.source)</SCRIPT>)"> -->
        /// </summary>   
        [Test]
        public void DivStyleExpressionNoQuotesXSSTest()
        {
            // Arrange
            var sanitizer = new HtmlSanitizer();


            // Act
            string htmlFragment = "<Div style=\"background-color: expression(<SCRIPT>a=/XSS/alert(a.source)</SCRIPT>)\">";
            string actual = sanitizer.Sanitize(htmlFragment);

            // Assert
            string expected = "<div></div>";
            Assert.That(actual, Is.EqualTo(expected).IgnoreCase);
        }

        /// <summary>
        /// A test for AnchorTag with US-ASCII encoding xss
        /// Example <!-- <A HREF="http://www.codeplex.com?url=¼script¾alert(¢XSS¢)¼/script¾">XSS</A> -->
        /// </summary>   
        [Test]
        public void AnchorTagUSASCIIEncodingXSSTest()
        {
            // Arrange
            var sanitizer = new HtmlSanitizer();


            // Act
            string htmlFragment = "<A HREF=\"http://www.codeplex.com?url=¼script¾alert(¢XSS¢)¼/script¾\">XSS</A>";
            string actual = sanitizer.Sanitize(htmlFragment);

            // Assert
            string expected = "<a href=\"http://www.codeplex.com/?url=¼script¾alert(¢XSS¢)¼/script¾\">XSS</a>";
            Assert.That(actual, Is.EqualTo(expected).IgnoreCase);
        }

        /// <summary>
        /// A test for AnchorTag with Downlevel-Hidden block xss
        /// </summary>   
        [Test]
        public void AnchorTagDownlevelHiddenBlockXSSTest()
        {
            // Arrange
            var sanitizer = new HtmlSanitizer();


            // Act
            string htmlFragment = "<A HREF=\"http://www.codeplex.com?url=<!--[if gte IE 4]><SCRIPT>alert('XSS');</SCRIPT><![endif]-->\">XSS</A>";
            string actual = sanitizer.Sanitize(htmlFragment);

            // Assert
            string expected = "<a>XSS</a>";
            Assert.That(actual, Is.EqualTo(expected).IgnoreCase);
        }

        /// <summary>
        /// A test for Div with Downlevel-Hidden block xss
        /// </summary>   
        [Test]
        public void DivDownlevelHiddenBlockXSSTest()
        {
            // Arrange
            var sanitizer = new HtmlSanitizer();


            // Act
            string htmlFragment = "<Div style=\"background-color: http://www.codeplex.com?url=<!--[if gte IE 4]><SCRIPT>alert('XSS');</SCRIPT><![endif]-->\">";
            string actual = sanitizer.Sanitize(htmlFragment);

            // Assert
            string expected = "<div></div>";
            Assert.That(actual, Is.EqualTo(expected).IgnoreCase);
        }

        /// <summary>
        /// A test for AnchorTag with Html Quotes Encapsulation 1 xss
        /// Example <!-- <A HREF="http://www.codeplex.com?url=<SCRIPT a=">" SRC="http://ha.ckers.org/xss.js"></SCRIPT>">XSS</A> -->
        /// </summary>   
        [Test]
        public void AnchorTagHtmlQuotesEncapsulation1XSSTest()
        {
            // Arrange
            var sanitizer = new HtmlSanitizer();


            // Act
            string htmlFragment = "<A HREF=\"http://www.codeplex.com?url=<SCRIPT a=\">\" SRC=\"http://ha.ckers.org/xss.js\"></SCRIPT>\">XSS</A>";
            string actual = sanitizer.Sanitize(htmlFragment);

            // Assert
            string expected = "<a>&quot; SRC=&quot;http://ha.ckers.org/xss.js&quot;&gt;&quot;&gt;XSS</a>";
            Assert.That(actual, Is.EqualTo(expected).IgnoreCase);
        }

        /// <summary>
        /// A test for Div with Html Quotes Encapsulation 1 xss
        /// Example <!-- <Div style="background-color: http://www.codeplex.com?url=<SCRIPT a=">" SRC="http://ha.ckers.org/xss.js"></SCRIPT>"> -->
        /// </summary>   
        [Test]
        public void DivHtmlQuotesEncapsulation1XSSTest()
        {
            // Arrange
            var sanitizer = new HtmlSanitizer();


            // Act
            string htmlFragment = "<Div style=\"background-color: http://www.codeplex.com?url=<SCRIPT a=\">\" SRC=\"http://ha.ckers.org/xss.js\"></SCRIPT>\">";
            string actual = sanitizer.Sanitize(htmlFragment);

            // Assert
            string expected = "<div>&quot; SRC=&quot;http://ha.ckers.org/xss.js&quot;&gt;&quot;&gt;</div>";
            Assert.That(actual, Is.EqualTo(expected).IgnoreCase);
        }

        /// <summary>
        /// A test for various legal fragments
        /// </summary>
        [Test]
        public void LegalTest()
        {
            // Arrange
            var sanitizer = new HtmlSanitizer();

            // Act
            string htmlFragment = "<div style=\"background-color: test\">";
            string actual = sanitizer.Sanitize(htmlFragment);

            // Assert
            string expected = "<div style=\"background-color: test\"></div>";
            Assert.That(actual, Is.EqualTo(expected).IgnoreCase);
        }

        /// <summary>
        /// More tests for legal fragments.
        /// </summary>
        [Test]
        public void MoreLegalTest()
        {
            // Arrange
            var sanitizer = new HtmlSanitizer();

            // Act
            string htmlFragment = "<div style=\"background-color: test\">Test<img src=\"http://www.example.com/test.gif\" style=\"background-image: url(http://www.example.com/bg.jpg); margin: 10px\"></div>";
            string actual = sanitizer.Sanitize(htmlFragment);

            // Assert
            string expected = "<div style=\"background-color: test\">Test<img style=\"background-image: url(http://www.example.com/bg.jpg); margin: 10px;\" src=\"http://www.example.com/test.gif\"></div>";
            Assert.That(actual, Is.EqualTo(expected).IgnoreCase);
        }

        /// <summary>
        /// Misc tests.
        /// </summary>
        [Test]
        public void MiscTest()
        {
            var sanitizer = new HtmlSanitizer();

            var html = @"<SCRIPT/SRC=""http://ha.ckers.org/xss.js""></SCRIPT>";
            var actual = sanitizer.Sanitize(html);
            var expected = "";
            Assert.That(actual, Is.EqualTo(expected).IgnoreCase);

            html = @"<DIV STYLE=""padding: &#49;px; mar/*xss*/gin: ex/*XSS*/pression(alert('xss')); background-image:\0075\0072\006C\0028\0022\006a\0061\0076\0061\0073\0063\0072\0069\0070\0074\003a\0061\006c\0065\0072\0074\0028\0027\0058\0053\0053\0027\0029\0022\0029"">";
            actual = sanitizer.Sanitize(html);
            expected = @"<div style=""padding: 1px""></div>";
            Assert.That(actual, Is.EqualTo(expected).IgnoreCase);

            html = @"<!--[if gte IE 4]><SCRIPT>alert('XSS');</SCRIPT><![endif]--><!-- Comment -->";
            actual = sanitizer.Sanitize(html);
            expected = "";
            Assert.That(actual, Is.EqualTo(expected).IgnoreCase);

            html = @"<STYLE>@im\port'\ja\vasc\ript:alert(""XSS"")';</STYLE>";
            actual = sanitizer.Sanitize(html);
            expected = "";
            Assert.That(actual, Is.EqualTo(expected).IgnoreCase);

            html = @"<div onload!#$%&()*~+-_.,:;?@[/|\]^`=alert(""XSS"")>";
            actual = sanitizer.Sanitize(html);
            expected = "<div></div>";
            Assert.That(actual, Is.EqualTo(expected).IgnoreCase);

            html = @"<SCRIPT/XSS SRC=""http://ha.ckers.org/xss.js""></SCRIPT>";
            actual = sanitizer.Sanitize(html);
            expected = "";
            Assert.That(actual, Is.EqualTo(expected).IgnoreCase);

            html = "<IMG SRC=javascript:alert(\"XSS\")>\"";
            actual = sanitizer.Sanitize(html);
            expected = "<img>&quot;";
            Assert.That(actual, Is.EqualTo(expected).IgnoreCase);

            html = "<IMG SRC=java\0script:alert(\"XSS\")>\"";
            actual = sanitizer.Sanitize(html);
            expected = "<img>&quot;";
            Assert.That(actual, Is.EqualTo(expected).IgnoreCase);

            html = @"<IMG SRC=""jav&#x0D;ascript:alert('XSS');"">";
            actual = sanitizer.Sanitize(html);
            expected = "<img>";
            Assert.That(actual, Is.EqualTo(expected).IgnoreCase);

            html = @"<IMG SRC=""jav&#x0A;ascript:alert('XSS');"">";
            actual = sanitizer.Sanitize(html);
            expected = "<img>";
            Assert.That(actual, Is.EqualTo(expected).IgnoreCase);

            html = @"<IMG SRC=""jav&#x09;ascript:alert('XSS');"">";
            actual = sanitizer.Sanitize(html);
            expected = "<img>";
            Assert.That(actual, Is.EqualTo(expected).IgnoreCase);

            html = @"<div style=""background-color: red""><sCRipt>hallo</scripT></div><a href=""#"">Test</a>";
            actual = sanitizer.Sanitize(html);
            expected = @"<div style=""background-color: red""></div><a href=""#"">Test</a>";
            Assert.That(actual, Is.EqualTo(expected).IgnoreCase);

            html = @"<IMG SRC=""jav	ascript:alert('XSS');"">";
            actual = sanitizer.Sanitize(html);
            expected = "<img>";
            Assert.That(actual, Is.EqualTo(expected).IgnoreCase);

            html = @"<IMG SRC="" &#14;  javascript:alert('XSS');"">";
            actual = sanitizer.Sanitize(html);
            expected = "<img>";
            Assert.That(actual, Is.EqualTo(expected).IgnoreCase);

            html = @"<IMG SRC=&#106;&#97;&#118;&#97;&#115;&#99;&#114;&#105;&#112;&#116;&#58;&#97;&#108;&#101;&#114;&#116;&#40;&#39;&#88;&#83;&#83;&#39;&#41;>";
            actual = sanitizer.Sanitize(html);
            expected = "<img>";
            Assert.That(actual, Is.EqualTo(expected).IgnoreCase);

            html = @"<IMG SRC=&#0000106&#0000097&#0000118&#0000097&#0000115&#0000099&#0000114&#0000105&#0000112&#0000116&#0000058&#0000097&#0000108&#0000101&#0000114&#0000116&#0000040&#0000039&#0000088&#0000083&#0000083&#0000039&#0000041>";
            actual = sanitizer.Sanitize(html);
            expected = "<img>";
            Assert.That(actual, Is.EqualTo(expected).IgnoreCase);

            html = @"<IMG SRC=&#x6A&#x61&#x76&#x61&#x73&#x63&#x72&#x69&#x70&#x74&#x3A&#x61&#x6C&#x65&#x72&#x74&#x28&#x27&#x58&#x53&#x53&#x27&#x29>";
            actual = sanitizer.Sanitize(html);
            expected = "<img>";
            Assert.That(actual, Is.EqualTo(expected).IgnoreCase);

            html = "<script>alert('xss')</script><div onload=\"alert('xss')\" style=\"background-color: test\">Test<img src=\"test.gif\" style=\"background-image: url(javascript:alert('xss')); margin: 10px\"></div>";
            actual = sanitizer.Sanitize(html, "http://www.example.com");
            expected = @"<div style=""background-color: test"">Test<img style=""margin: 10px"" src=""http://www.example.com/test.gif""></div>";
            Assert.That(actual, Is.EqualTo(expected).IgnoreCase);
        }

        /// <summary>
        /// Tests disallowed tags.
        /// </summary>
        [Test]
        public void DisallowedTagTest()
        {
            var sanitizer = new HtmlSanitizer();

            var html = @"<bla>Hallo</bla>";
            var actual = sanitizer.Sanitize(html);
            var expected = "";
            Assert.That(actual, Is.EqualTo(expected).IgnoreCase);
        }

        /// <summary>
        /// Tests disallowed HTML attributes.
        /// </summary>
        [Test]
        public void DisallowedAttributeTest()
        {
            var sanitizer = new HtmlSanitizer();

            var html = @"<div bla=""test"">Test</div>";
            var actual = sanitizer.Sanitize(html);
            var expected = @"<div>Test</div>";
            Assert.That(actual, Is.EqualTo(expected).IgnoreCase);
        }

        /// <summary>
        /// Tests sanitization of attributes that contain a URL.
        /// </summary>
        [Test]
        public void UrlAttributeTest()
        {
            var sanitizer = new HtmlSanitizer();

            var html = @"<a href=""mailto:test@example.com"">test</a>";
            var actual = sanitizer.Sanitize(html);
            var expected = @"<a>test</a>";
            Assert.That(actual, Is.EqualTo(expected).IgnoreCase);

            html = @"<a href=""http:xxx"">test</a>";
            actual = sanitizer.Sanitize(html);
            expected = @"<a>test</a>";
            Assert.That(actual, Is.EqualTo(expected).IgnoreCase);

            html = @"<a href=""folder/file.jpg"">test</a>";
            actual = sanitizer.Sanitize(html, @"http://www.example.com");
            expected = @"<a href=""http://www.example.com/folder/file.jpg"">test</a>";
            Assert.That(actual, Is.EqualTo(expected).IgnoreCase);
        }

        /// <summary>
        /// Tests disallowed css properties.
        /// </summary>
        [Test]
        public void DisallowedStyleTest()
        {
            var sanitizer = new HtmlSanitizer();

            var html = @"<div style=""margin: 8px; bla: 1px"">test</div>";
            var actual = sanitizer.Sanitize(html);
            var expected = @"<div style=""margin: 8px"">test</div>";
            Assert.That(actual, Is.EqualTo(expected).IgnoreCase);
        }

        /// <summary>
        /// Tests sanitization of URLs that are contained in CSS property values.
        /// </summary>
        [Test]
        public void UrlStyleTest()
        {
            var sanitizer = new HtmlSanitizer();

            var html = @"<div style=""padding: 10px; background-image: url(mailto:test@example.com)""></div>";
            var actual = sanitizer.Sanitize(html);
            var expected = @"<div style=""padding: 10px""></div>";
            Assert.That(actual, Is.EqualTo(expected).IgnoreCase);

            html = @"<div style=""padding: 10px; background-image: url(folder/file.jpg)""></div>";
            actual = sanitizer.Sanitize(html, @"http://www.example.com");
            expected = @"<div style=""padding: 10px; background-image: url(http://www.example.com/folder/file.jpg);""></div>";
            Assert.That(actual, Is.EqualTo(expected).IgnoreCase);
        }

        // test below from http://genshi.edgewall.org/

        [Test]
        public void SanitizeUnchangedTest()
        {
            var sanitizer = new HtmlSanitizer();
            var html = @"<a href=""#"">fo<br />o</a>";
            Assert.That(sanitizer.Sanitize(html), Is.EqualTo(@"<a href=""#"">fo<br>o</a>").IgnoreCase);

            html = @"<a href=""#with:colon"">foo</a>";
            Assert.That(sanitizer.Sanitize(html), Is.EqualTo(@"<a>foo</a>").IgnoreCase);
        }

        [Test]
        public void SanitizeEscapeTextTest()
        {
            var sanitizer = new HtmlSanitizer();
            var html = @"<a href=""#"">fo&amp;</a>";
            Assert.That(sanitizer.Sanitize(html), Is.EqualTo(@"<a href=""#"">fo&amp;</a>").IgnoreCase);

            html = @"<a href=""#"">&lt;foo&gt;</a>";
            Assert.That(sanitizer.Sanitize(html), Is.EqualTo(@"<a href=""#"">&lt;foo&gt;</a>").IgnoreCase);
        }

        [Test]
        public void SanitizeEntityrefTextTest()
        {
            var sanitizer = new HtmlSanitizer();
            var html = @"<a href=""#"">fo&ouml;</a>";
            Assert.That(sanitizer.Sanitize(html), Is.EqualTo(@"<a href=""#"">fo&#246;</a>").IgnoreCase);
        }

        [Test]
        public void SanitizeEscapeAttrTest()
        {
            var sanitizer = new HtmlSanitizer();
            var html = @"<div title=""&lt;foo&gt;""></div>";
            Assert.That(sanitizer.Sanitize(html), Is.EqualTo(@"<div title=""&lt;foo&gt;""></div>").IgnoreCase);
        }

        [Test]
        public void SanitizeCloseEmptyTagTest()
        {
            var sanitizer = new HtmlSanitizer();
            var html = @"<a href=""#"">fo<br>o</a>";
            Assert.That(sanitizer.Sanitize(html), Is.EqualTo(@"<a href=""#"">fo<br>o</a>").IgnoreCase);
        }

        [Test]
        public void SanitizeInvalidEntityTest()
        {
            var sanitizer = new HtmlSanitizer();
            var html = @"&junk;";
            Assert.That(sanitizer.Sanitize(html), Is.EqualTo(@"&amp;junk;").IgnoreCase);
        }

        [Test]
        public void SanitizeRemoveScriptElemTest()
        {
            var sanitizer = new HtmlSanitizer();
            var html = @"<script>alert(""Foo"")</script>";
            Assert.That(sanitizer.Sanitize(html), Is.EqualTo(@"").IgnoreCase);
            html = @"<SCRIPT SRC=""http://example.com/""></SCRIPT>";
            Assert.That(sanitizer.Sanitize(html), Is.EqualTo(@"").IgnoreCase);
        }

        [Test]
        public void SanitizeRemoveOnclickAttrTest()
        {
            var sanitizer = new HtmlSanitizer();
            var html = @"<div onclick=\'alert(""foo"")\' />";
            Assert.That(sanitizer.Sanitize(html), Is.EqualTo(@"<div></div>").IgnoreCase);
        }

        [Test]
        public void SanitizeRemoveCommentsTest()
        {
            var sanitizer = new HtmlSanitizer();
            var html = @"<div><!-- conditional comment crap --></div>";
            Assert.That(sanitizer.Sanitize(html), Is.EqualTo(@"<div></div>").IgnoreCase);
        }

        [Test]
        public void SanitizeRemoveStyleScriptsTest()
        {
            var sanitizer = new HtmlSanitizer();
            // Inline style with url() using javascript: scheme
            var html = @"<DIV STYLE='background: url(javascript:alert(""foo""))'>";
            Assert.That(sanitizer.Sanitize(html), Is.EqualTo(@"<div></div>").IgnoreCase);
            // Inline style with url() using javascript: scheme, using control char
            html = @"<DIV STYLE='background: url(&#1;javascript:alert(""foo""))'>";
            Assert.That(sanitizer.Sanitize(html), Is.EqualTo(@"<div></div>").IgnoreCase);
            // Inline style with url() using javascript: scheme, in quotes
            html = @"<DIV STYLE='background: url(""javascript:alert(foo)"")'>";
            Assert.That(sanitizer.Sanitize(html), Is.EqualTo(@"<div></div>").IgnoreCase);
            // IE expressions in CSS not allowed
            html = @"<DIV STYLE='width: expression(alert(""foo""));'>";
            Assert.That(sanitizer.Sanitize(html), Is.EqualTo(@"<div></div>").IgnoreCase);
            html = @"<DIV STYLE='width: e/**/xpression(alert(""foo""));'>";
            Assert.That(sanitizer.Sanitize(html), Is.EqualTo(@"<div></div>").IgnoreCase);
            html = @"<DIV STYLE='background: url(javascript:alert(""foo""));color: #fff'>";
            Assert.That(sanitizer.Sanitize(html), Is.EqualTo(@"<div style=""color: #fff""></div>").IgnoreCase);

            // Inline style with url() using javascript: scheme, using unicode
            // escapes
            html = @"<DIV STYLE='background: \75rl(javascript:alert(""foo""))'>";
            Assert.That(sanitizer.Sanitize(html), Is.EqualTo(@"<div></div>").IgnoreCase);
            html = @"<DIV STYLE='background: \000075rl(javascript:alert(""foo""))'>";
            Assert.That(sanitizer.Sanitize(html), Is.EqualTo(@"<div></div>").IgnoreCase);
            html = @"<DIV STYLE='background: \75 rl(javascript:alert(""foo""))'>";
            Assert.That(sanitizer.Sanitize(html), Is.EqualTo(@"<div></div>").IgnoreCase);
            html = @"<DIV STYLE='background: \000075 rl(javascript:alert(""foo""))'>";
            Assert.That(sanitizer.Sanitize(html), Is.EqualTo(@"<div></div>").IgnoreCase);
            html = @"<DIV STYLE='background: \000075
rl(javascript:alert(""foo""))'>";
            Assert.That(sanitizer.Sanitize(html), Is.EqualTo(@"<div></div>").IgnoreCase);
        }

        [Test]
        public void SanitizeRemoveStylePhishingTest()
        {
            var sanitizer = new HtmlSanitizer();
            // The position property is not allowed
            var html = @"<div style=""position:absolute;top:0""></div>";
            Assert.That(sanitizer.Sanitize(html), Is.EqualTo(@"<div style=""top: 0""></div>").IgnoreCase);
            // Normal margins get passed through
            html = @"<div style=""margin:10px 20px""></div>";
            Assert.That(sanitizer.Sanitize(html), Is.EqualTo(@"<div style=""margin: 10px 20px""></div>").IgnoreCase);
        }

        [Test]
        public void SanitizeRemoveSrcJavascriptTest()
        {
            var sanitizer = new HtmlSanitizer();
            var html = @"<img src=\'javascript:alert(""foo"")\'>";
            Assert.That(sanitizer.Sanitize(html), Is.EqualTo(@"<img>").IgnoreCase);
            // Case-insensitive protocol matching
            html = @"<IMG SRC=\'JaVaScRiPt:alert(""foo"")\'>";
            Assert.That(sanitizer.Sanitize(html), Is.EqualTo(@"<img>").IgnoreCase);
            // Grave accents (not parsed)
            // Protocol encoded using UTF-8 numeric entities
            html = @"<IMG SRC=\'&#106;&#97;&#118;&#97;&#115;&#99;&#114;&#105;&#112;&#116;&#58;alert(""foo"")\'>";
            Assert.That(sanitizer.Sanitize(html), Is.EqualTo(@"<img>").IgnoreCase);
            // Protocol encoded using UTF-8 numeric entities without a semicolon
            // (which is allowed because the max number of digits is used)
            html = @"<IMG SRC=\'&#0000106&#0000097&#0000118&#0000097&#0000115&#0000099&#0000114&#0000105&#0000112&#0000116&#0000058alert(""foo"")\'>";
            Assert.That(sanitizer.Sanitize(html), Is.EqualTo(@"<img>").IgnoreCase);
            // Protocol encoded using UTF-8 numeric hex entities without a semicolon
            // (which is allowed because the max number of digits is used)
            html = @"<IMG SRC=\'&#x6A&#x61&#x76&#x61&#x73&#x63&#x72&#x69&#x70&#x74&#x3A;alert(""foo"")\'>";
            Assert.That(sanitizer.Sanitize(html), Is.EqualTo(@"<img>").IgnoreCase);
            // Embedded tab character in protocol
            html = @"<IMG SRC=\'jav\tascript:alert(""foo"");\'>";
            Assert.That(sanitizer.Sanitize(html), Is.EqualTo(@"<img>").IgnoreCase);
            // Embedded tab character in protocol, but encoded this time
            html = @"<IMG SRC=\'jav&#x09;ascript:alert(""foo"");\'>";
            Assert.That(sanitizer.Sanitize(html), Is.EqualTo(@"<img>").IgnoreCase);
        }

        [Test]
        public void SanitizeExpressionTest()
        {
            var sanitizer = new HtmlSanitizer();
            var html = @"<div style=""top:expression(alert())"">XSS</div>";
            Assert.That(sanitizer.Sanitize(html), Is.EqualTo(@"<div>XSS</div>").IgnoreCase);
        }

        [Test]
        public void capitalExpressionTest()
        {
            var sanitizer = new HtmlSanitizer();
            var html = @"<div style=""top:EXPRESSION(alert())"">XSS</div>";
            Assert.That(sanitizer.Sanitize(html), Is.EqualTo(@"<div>XSS</div>").IgnoreCase);
        }

        [Test]
        public void SanitizeUrlWithJavascriptTest()
        {
            var sanitizer = new HtmlSanitizer();
            var html = @"<div style=""background-image:url(javascript:alert())"">XSS</div>";
            Assert.That(sanitizer.Sanitize(html), Is.EqualTo(@"<div>XSS</div>").IgnoreCase);
        }

        [Test]
        public void SanitizeCapitalUrlWithJavascriptTest()
        {
            var sanitizer = new HtmlSanitizer();
            var html = @"<div style=""background-image:URL(javascript:alert())"">XSS</div>";
            Assert.That(sanitizer.Sanitize(html), Is.EqualTo(@"<div>XSS</div>").IgnoreCase);
        }

        [Test]
        public void SanitizeUnicodeEscapesTest()
        {
            var sanitizer = new HtmlSanitizer();
            var html = @"<div style=""top:exp\72 ess\000069 on(alert())"">XSS</div>";
            Assert.That(sanitizer.Sanitize(html), Is.EqualTo(@"<div>XSS</div>").IgnoreCase);
        }

        [Test]
        public void SanitizeBackslashWithoutHexTest()
        {
            var sanitizer = new HtmlSanitizer();
            var html = @"<div style=""top:e\xp\ression(alert())"">XSS</div>";
            Assert.That(sanitizer.Sanitize(html), Is.EqualTo(@"<div>XSS</div>").IgnoreCase);
            html = @"<div style=""top:e\\xp\\ression(alert())"">XSS</div>";
            Assert.That(sanitizer.Sanitize(html), Is.EqualTo(@"<div style=""top: e\\xp\\ression(alert())"">XSS</div>").IgnoreCase);
        }

        [Test]
        public void SanitizeUnsafePropsTest()
        {
            var sanitizer = new HtmlSanitizer();
            var html = @"<div style=""POSITION:RELATIVE"">XSS</div>";
            Assert.That(sanitizer.Sanitize(html), Is.EqualTo(@"<div>XSS</div>").IgnoreCase);

            html = @"<div style=""behavior:url(test.htc)"">XSS</div>";
            Assert.That(sanitizer.Sanitize(html), Is.EqualTo(@"<div>XSS</div>").IgnoreCase);

            html = @"<div style=""-ms-behavior:url(test.htc) url(#obj)"">XSS</div>";
            Assert.That(sanitizer.Sanitize(html), Is.EqualTo(@"<div>XSS</div>").IgnoreCase);

            html = @"<div style=""-o-link:'javascript:alert(1)';-o-link-source:current"">XSS</div>";
            Assert.That(sanitizer.Sanitize(html), Is.EqualTo(@"<div>XSS</div>").IgnoreCase);

            html = @"<div style=""-moz-binding:url(xss.xbl)"">XSS</div>";
            Assert.That(sanitizer.Sanitize(html), Is.EqualTo(@"<div>XSS</div>").IgnoreCase);
        }

        [Test]
        public void SanitizeCssHackTest()
        {
            var sanitizer = new HtmlSanitizer();
            var html = @"<div style=""*position:static"">XSS</div>";
            Assert.That(sanitizer.Sanitize(html), Is.EqualTo(@"<div>XSS</div>").IgnoreCase);
        }

        [Test]
        public void SanitizePropertyNameTest()
        {
            var sanitizer = new HtmlSanitizer();
            var html = @"<div style=""display:none;border-left-color:red;userDefined:1;-moz-user-selct:-moz-all"">prop</div>";
            Assert.That(sanitizer.Sanitize(html), Is.EqualTo(@"<div style=""display: none; border-left-color: red;"">prop</div>").IgnoreCase);
        }

        [Test]
        public void SanitizeUnicodeExpressionTest()
        {
            var sanitizer = new HtmlSanitizer();
            // Fullwidth small letters
            var html = @"<div style=""top:ｅｘｐｒｅｓｓｉｏｎ(alert())"">XSS</div>";
            Assert.That(sanitizer.Sanitize(html), Is.EqualTo(@"<div>XSS</div>").IgnoreCase);
            // Fullwidth capital letters
            html = @"<div style=""top:ＥＸＰＲＥＳＳＩＯＮ(alert())"">XSS</div>";
            Assert.That(sanitizer.Sanitize(html), Is.EqualTo(@"<div>XSS</div>").IgnoreCase);
            // IPA extensions
            html = @"<div style=""top:expʀessɪoɴ(alert())"">XSS</div>";
            Assert.That(sanitizer.Sanitize(html), Is.EqualTo(@"<div>XSS</div>").IgnoreCase);
        }

        [Test]
        public void SanitizeUnicodeUrlTest()
        {
            var sanitizer = new HtmlSanitizer();
            // IPA extensions
            var html = @"<div style=""background-image:uʀʟ(javascript:alert())"">XSS</div>";
            Assert.That(sanitizer.Sanitize(html), Is.EqualTo(@"<div>XSS</div>").IgnoreCase);
        }

        [Test]
        public void RemovingTagEventTest()
        {
            var sanitizer = new HtmlSanitizer();
            sanitizer.RemovingTag += (s, e) => e.Cancel = e.Tag.NodeName == "BLINK";
            var html = @"<div><script></script><blink>Test</blink></div>";
            Assert.That(sanitizer.Sanitize(html), Is.EqualTo(@"<div><blink>Test</blink></div>").IgnoreCase);
        }

        [Test]
        public void RemovingAttributeEventTest()
        {
            var sanitizer = new HtmlSanitizer();
            sanitizer.RemovingAttribute += (s, e) => e.Cancel = e.Attribute.Key == "onclick";
            var html = @"<div alt=""alt"" onclick=""test"" onload=""test""></div>";
            Assert.That(sanitizer.Sanitize(html), Is.EqualTo(@"<div alt=""alt"" onclick=""test""></div>").IgnoreCase);
        }

        [Test]
        public void RemovingStyleEventTest()
        {
            var sanitizer = new HtmlSanitizer();
            sanitizer.RemovingStyle += (s, e) => e.Cancel = e.Style.Key == "test";
            var html = @"<div style=""background: 0; test: xyz; bad: bad;""></div>";
            Assert.That(sanitizer.Sanitize(html), Is.EqualTo(@"<div style=""background: 0; test: xyz;""></div>").IgnoreCase);
        }

        [Test]
        public void AllowDataAttributesTest()
        {
            var sanitizer = new HtmlSanitizer();
            sanitizer.AllowDataAttributes = true;
            var html = @"<div data-test1=""value x""></div>";
            Assert.That(sanitizer.Sanitize(html), Is.EqualTo(html).IgnoreCase);
        }

        [Test]
        public void AllowDataAttributesCaseTest()
        {
            var sanitizer = new HtmlSanitizer();
            sanitizer.AllowDataAttributes = true;
            var html = @"<div DAta-test1=""value x""></div>";
            Assert.That(sanitizer.Sanitize(html), Is.EqualTo(html).IgnoreCase);
        }

        [Test]
        public void AllowDataAttributesOffTest()
        {
            var sanitizer = new HtmlSanitizer();
            sanitizer.AllowDataAttributes = false;
            var html = @"<div data-test1=""value x""></div>";
            Assert.That(sanitizer.Sanitize(html), Is.EqualTo(@"<div></div>").IgnoreCase);
        }
    }
}

#pragma warning restore 1591

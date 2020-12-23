using AngleSharp;
using AngleSharp.Css.Dom;
using AngleSharp.Css.Parser;
using AngleSharp.Dom;
using AngleSharp.Html.Dom;
using AngleSharp.Html.Parser;
using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Reflection;
using System.Text;
using System.Text.RegularExpressions;
using System.Threading;
using Xunit;

// Tests based on tests from http://roadkill.codeplex.com/

// To create unit tests in this class reference is taken from
// https://www.owasp.org/index.php/XSS_(Cross_Site_Scripting)_Prevention_Cheat_Sheet#RULE_.232_-_Attribute_Escape_Before_Inserting_Untrusted_Data_into_HTML_Common_Attributes
// and http://ha.ckers.org/xss.html

// disable XML comments warnings
#pragma warning disable 1591

namespace Ganss.XSS.Tests
{
    public class HtmlSanitizerFixture
    {
        public HtmlSanitizer Sanitizer { get; set; } = new HtmlSanitizer();
    }

    /// <summary>
    /// Tests for <see cref="HtmlSanitizer"/>.
    /// </summary>
    public class HtmlSanitizerTests: IClassFixture<HtmlSanitizerFixture>
    {
        public HtmlSanitizer Sanitizer { get; set; }

        public HtmlSanitizerTests(HtmlSanitizerFixture fixture)
        {
            Encoding.RegisterProvider(CodePagesEncodingProvider.Instance);
            Sanitizer = fixture.Sanitizer;
        }

        /// <summary>
        /// A test for Xss locator
        /// </summary>
        [Fact]
        public void XSSLocatorTest()
        {
            // Arrange
            var sanitizer = Sanitizer;

            // Act
            string htmlFragment = "<a href=\"'';!--\"<XSS>=&{()}\">";
            string actual = sanitizer.Sanitize(htmlFragment);

            // Assert
            string expected = @"<a href=""'';!--"">=&amp;{()}""&gt;</a>";
            Assert.Equal(expected, actual, ignoreCase: true);
        }

        /// <summary>
        /// A test for Image Xss vector
        /// Example <!-- <IMG SRC="javascript:alert('XSS');"> -->
        /// </summary>
        [Fact]
        public void ImageXSS1Test()
        {
            // Arrange
            var sanitizer = Sanitizer;


            // Action
            string htmlFragment = "<IMG SRC=\"javascript:alert('XSS');\">";
            string actual = sanitizer.Sanitize(htmlFragment);

            // Assert
            string expected = "<img>";
            Assert.Equal(expected, actual, ignoreCase: true);
        }

        /// <summary>
        /// A test for Image Xss vector without quotes and semicolon.
        /// Example <!-- <IMG SRC=javascript:alert('XSS')> -->
        /// </summary>
        [Fact]
        public void ImageXSS2Test()
        {
            // Arrange
            var sanitizer = Sanitizer;


            // Act
            string htmlFragment = "<IMG SRC=javascript:alert('XSS')>";
            string actual = sanitizer.Sanitize(htmlFragment);

            // Assert
            string expected = "<IMG>";
            Assert.Equal(expected, actual, ignoreCase: true);
        }

        /// <summary>
        /// A test for Image xss vector with case insensitive.
        /// Example <!-- <IMG SRC=JaVaScRiPt:alert('XSS')> -->
        /// </summary>
        [Fact]
        public void ImageCaseInsensitiveXSSTest()
        {
            // Arrange
            var sanitizer = Sanitizer;


            // Act
            string htmlFragment = "<IMG SRC=JaVaScRiPt:alert('XSS')>";
            string actual = sanitizer.Sanitize(htmlFragment);

            // Assert
            string expected = "<IMG>";
            Assert.Equal(expected, actual, ignoreCase: true);
        }

        /// <summary>
        /// A test for Image Xss vector with Html entities
        /// Example <!-- <IMG SRC=javascript:alert(&quot;XSS&quot;)> -->
        /// </summary>
        [Fact]
        public void ImageHtmlEntitiesXSSTest()
        {
            // Arrange
            var sanitizer = Sanitizer;


            // Act
            string htmlFragment = "<IMG SRC=javascript:alert(&quot;XSS&quot;)>";
            string actual = sanitizer.Sanitize(htmlFragment);

            // Assert
            string expected = "<IMG>";
            Assert.Equal(expected, actual, ignoreCase: true);
        }

        /// <summary>
        /// A test for Image Xss vector with grave accent
        /// Example <!-- <IMG SRC=`javascript:alert("RSnake says, 'XSS'")`> -->
        /// </summary>
        [Fact]
        public void ImageGraveAccentXSSTest()
        {
            // Arrange
            var sanitizer = Sanitizer;


            // Act
            string htmlFragment = "<IMG SRC=`javascript:alert(\"RSnake says, 'XSS'\")`>";
            string actual = sanitizer.Sanitize(htmlFragment);

            // Assert
            string expected = "<img>";
            Assert.Equal(expected, actual, ignoreCase: true);
        }

        /// <summary>
        /// A test for Image Xss vector with malformed
        /// Example <!-- <IMG \"\"\"><SCRIPT>alert(\"XSS\")</SCRIPT>\"> -->
        /// </summary>
        [Fact]
        public void ImageMalformedXSSTest()
        {
            // Arrange
            var sanitizer = Sanitizer;


            // Act
            string htmlFragment = "<IMG \"\"\"><SCRIPT>alert(\"XSS\")</SCRIPT>\">";
            string actual = sanitizer.Sanitize(htmlFragment);

            // Assert
            string expected = "<img>\"&gt;";
            Assert.Equal(expected, actual, ignoreCase: true);
        }

        /// <summary>
        /// A test for Image Xss vector with ImageFromCharCode
        /// Example <!-- <IMG SRC=javascript:alert(String.fromCharCode(88,83,83))> -->
        /// </summary>
        [Fact]
        public void ImageFromCharCodeXSSTest()
        {
            // Arrange
            var sanitizer = Sanitizer;


            // Act
            string htmlFragment = "<IMG SRC=javascript:alert(String.fromCharCode(88,83,83))>";
            string actual = sanitizer.Sanitize(htmlFragment);

            // Assert
            string expected = "<img>";
            Assert.Equal(expected, actual, ignoreCase: true);
        }

        /// <summary>
        /// A test for Image Xss vector with UTF-8 Unicode
        /// Example <!-- <IMG SRC=&#106;&#97;&#118;&#97;&#115;&#99;&#114;&#105;&#112;&#116;&#58;&#97;&#108;&#101;&#114;&#116;&#40;&#39;&#88;&#83;&#83;&#39;&#41;> -->
        /// </summary>
        [Fact]
        public void ImageUTF8UnicodeXSSTest()
        {
            // Arrange
            var sanitizer = Sanitizer;


            // Act
            string htmlFragment = "<IMG SRC=&#106;&#97;&#118;&#97;&#115;&#99;&#114;&#105;&#112;&#116;&#58;&#97;&#108;&#101;&#114;&#116;&#40;&#39;&#88;&#83;&#83;&#39;&#41;>";
            string actual = sanitizer.Sanitize(htmlFragment);

            // Assert
            string expected = "<img>";
            Assert.Equal(expected, actual, ignoreCase: true);
        }

        /// <summary>
        /// A test for Image Xss vector with Long UTF-8 Unicode
        /// Example <!-- <IMG SRC=&#0000106&#0000097&#0000118&#0000097&#0000115&#0000099&#0000114&#0000105&#0000112&#0000116&#0000058&#0000097&#0000108&#0000101&#0000114&#0000116&#0000040&#0000039&#0000088&#0000083&#0000083&#0000039&#0000041> -->
        /// </summary>
        [Fact]
        public void ImageLongUTF8UnicodeXSSTest()
        {
            // Arrange
            var sanitizer = Sanitizer;


            // Act
            string htmlFragment = "<IMG SRC=&#0000106&#0000097&#0000118&#0000097&#0000115&#0000099&#0000114&#0000105&#0000112&#0000116&#0000058&#0000097&#0000108&#0000101&#0000114&#0000116&#0000040&#0000039&#0000088&#0000083&#0000083&#0000039&#0000041>";
            string actual = sanitizer.Sanitize(htmlFragment);

            // Assert
            string expected = "<img>";
            Assert.Equal(expected, actual, ignoreCase: true);
        }

        /// <summary>
        /// A test for Image Xss vector with Hex encoding without semicolon
        /// Example <!-- <IMG SRC=&#x6A&#x61&#x76&#x61&#x73&#x63&#x72&#x69&#x70&#x74&#x3A&#x61&#x6C&#x65&#x72&#x74&#x28&#x27&#x58&#x53&#x53&#x27&#x29> -->
        /// </summary>
        [Fact]
        public void ImageHexEncodeXSSTest()
        {
            // Arrange
            var sanitizer = Sanitizer;


            // Act
            string htmlFragment = "<IMG SRC=&#x6A&#x61&#x76&#x61&#x73&#x63&#x72&#x69&#x70&#x74&#x3A&#x61&#x6C&#x65&#x72&#x74&#x28&#x27&#x58&#x53&#x53&#x27&#x29>";
            string actual = sanitizer.Sanitize(htmlFragment);

            // Assert
            string expected = "<img>";
            Assert.Equal(expected, actual, ignoreCase: true);
        }

        /// <summary>
        /// A test for Image Xss vector with embedded tab
        /// Example <!-- <IMG SRC=\"jav	ascript:alert('XSS');\"> -->
        /// </summary>
        [Fact]
        public void ImageEmbeddedTabXSSTest()
        {
            // Arrange
            var sanitizer = Sanitizer;


            // Act
            string htmlFragment = "<IMG SRC=\"jav	ascript:alert('XSS');\">";
            string actual = sanitizer.Sanitize(htmlFragment);

            // Assert
            string expected = "<img>";
            Assert.Equal(expected, actual, ignoreCase: true);
        }

        /// <summary>
        /// A test for Image Xss vector with embedded encoded tab
        /// Example <!-- <IMG SRC="jav&#x09;ascript:alert('XSS');"> -->
        /// </summary>
        [Fact]
        public void ImageEmbeddedEncodedTabXSSTest()
        {
            // Arrange
            var sanitizer = Sanitizer;


            // Act
            string htmlFragment = "<IMG SRC=\"jav&#x09;ascript:alert('XSS');\">";
            string actual = sanitizer.Sanitize(htmlFragment);

            // Assert
            string expected = "<img>";
            Assert.Equal(expected, actual, ignoreCase: true);
        }

        /// <summary>
        /// A test for Image Xss vector with embedded new line
        /// Example <!-- <IMG SRC="jav&#x0A;ascript:alert('XSS');"> -->
        /// </summary>
        [Fact]
        public void ImageEmbeddedNewLineXSSTest()
        {
            // Arrange
            var sanitizer = Sanitizer;


            // Act
            string htmlFragment = "<IMG SRC=\"jav&#x0A;ascript:alert('XSS');\">";
            string actual = sanitizer.Sanitize(htmlFragment);

            // Assert
            string expected = "<img>";
            Assert.Equal(expected, actual, ignoreCase: true);
        }

        /// <summary>
        /// A test for Image Xss vector with embedded carriage return
        /// Example <!-- <IMG SRC=\"jav&#x0D;ascript:alert('XSS');\"> -->
        /// </summary>
        [Fact]
        public void ImageEmbeddedCarriageReturnXSSTest()
        {
            // Arrange
            var sanitizer = Sanitizer;


            // Act
            string htmlFragment = "<IMG SRC=\"jav&#x0D;ascript:alert('XSS');\">";
            string actual = sanitizer.Sanitize(htmlFragment);

            // Assert
            string expected = "<img>";
            Assert.Equal(expected, actual, ignoreCase: true);
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
        [Fact]
        public void ImageMultilineInjectedXSSTest()
        {
            // Arrange
            var sanitizer = Sanitizer;


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
            Assert.Equal(expected, actual, ignoreCase: true);
        }

        /// <summary>
        /// A test for Image Xss vector with Null breaks up Javascript directive
        /// Example <!-- perl -e 'print "<IMG SRC=java\0script:alert(\"XSS\")>";' > out -->
        /// </summary>
        [Fact]
        public void ImageNullBreaksUpXSSTest1()
        {
            // Arrange
            var sanitizer = Sanitizer;


            // Act
            string htmlFragment = "<IMG SRC=java\0script:alert(\"XSS\")>";
            string actual = sanitizer.Sanitize(htmlFragment);

            // Assert
            string expected = "<img>";
            Assert.Equal(expected, actual, ignoreCase: true);
        }

        /// <summary>
        /// A test for Image Xss vector with Null breaks up cross site scripting vector
        /// Example <!-- <image src=" perl -e 'print "<SCR\0IPT>alert(\"XSS\")</SCR\0IPT>";' > out "> -->
        /// </summary>
        [Fact]
        public void ImageNullBreaksUpXSSTest2()
        {
            // Arrange
            var sanitizer = Sanitizer;


            // Act
            string htmlFragment = "<SCR\0IPT>alert(\"XSS\")</SCR\0IPT>";
            string actual = sanitizer.Sanitize(htmlFragment);

            // Assert
            string expected = "";
            Assert.Equal(expected, actual, ignoreCase: true);
        }

        /// <summary>
        /// A test for Image Xss vector with spaces and Meta characters
        /// Example <!-- <IMG SRC=" &#14;  javascript:alert('XSS');"> -->
        /// </summary>
        [Fact]
        public void ImageSpaceAndMetaCharXSSTest()
        {
            // Arrange
            var sanitizer = Sanitizer;


            // Act
            string htmlFragment = "<IMG SRC=\" &#14;  javascript:alert('XSS');\">";
            string actual = sanitizer.Sanitize(htmlFragment);

            // Assert
            string expected = "<img>";
            Assert.Equal(expected, actual, ignoreCase: true);
        }

        /// <summary>
        /// A test for Image Xss vector with half open html
        /// Example <!-- <IMG SRC="javascript:alert('XSS')" -->
        /// </summary>
        [Fact]
        public void ImageHalfOpenHtmlXSSTest()
        {
            // Arrange
            var sanitizer = Sanitizer;


            // Act
            string htmlFragment = "<IMG SRC=\"javascript:alert('XSS')\"";
            string actual = sanitizer.Sanitize(htmlFragment);

            // Assert
            string expected = "";
            Assert.Equal(expected, actual, ignoreCase: true);
        }

        /// <summary>
        /// A test for Image Xss vector with double open angle bracket
        /// Example <!-- <image src=http://ha.ckers.org/scriptlet.html < -->
        /// </summary>
        [Fact]
        public void ImageDoubleOpenAngleBracketXSSTest()
        {
            // Arrange
            var sanitizer = Sanitizer;

            // Act
            string htmlFragment = "<image src=http://ha.ckers.org/scriptlet.html <";
            string actual = sanitizer.Sanitize(htmlFragment);

            // Assert
            string expected = "";
            Assert.Equal(expected, actual, ignoreCase: true);
        }

        /// <summary>
        /// A test for Dic Xss vector with Javascript escaping
        /// Example <!-- <div style="\";alert('XSS');//"> -->
        /// </summary>
        [Fact]
        public void DivJavascriptEscapingXSSTest()
        {
            // Arrange
            var sanitizer = Sanitizer;


            // Act
            string htmlFragment = "<div style=\"\";alert('XSS');//\">";
            string actual = sanitizer.Sanitize(htmlFragment);

            // Assert
            string expected = "<div style=\"\"></div>";
            Assert.Equal(expected, actual, ignoreCase: true);
        }

        /// <summary>
        /// A test for Image Xss vector with input image
        /// Example <!-- <INPUT TYPE="IMAGE" SRC="javascript:alert('XSS');"> -->
        /// </summary>
        [Fact]
        public void ImageInputXSSTest()
        {
            // Arrange
            var sanitizer = Sanitizer;


            // Act
            string htmlFragment = "<INPUT TYPE=\"IMAGE\" SRC=\"javascript:alert('XSS');\">";
            string actual = sanitizer.Sanitize(htmlFragment);

            // Assert
            string expected = "<input type=\"image\">";
            Assert.Equal(expected, actual, ignoreCase: true);
        }

        /// <summary>
        /// A test for Image Xss vector with Dynsrc
        /// Example <!-- <IMG DYNSRC="javascript:alert('XSS')"> -->
        /// </summary>
        [Fact]
        public void ImageDynsrcXSSTest()
        {
            // Arrange
            var sanitizer = Sanitizer;


            // Act
            string htmlFragment = "<IMG DYNSRC=\"javascript:alert('XSS')\">";
            string actual = sanitizer.Sanitize(htmlFragment);

            // Assert
            string expected = "<img>";
            Assert.Equal(expected, actual, ignoreCase: true);
        }

        /// <summary>
        /// A test for Image Xss vector with Lowsrc
        /// Example <!-- <IMG LOWSRC="javascript:alert('XSS')"> -->
        /// </summary>
        [Fact]
        public void ImageLowsrcXSSTest()
        {
            // Arrange
            var sanitizer = Sanitizer;


            // Act
            string htmlFragment = "<IMG LOWSRC=\"javascript:alert('XSS')\">";
            string actual = sanitizer.Sanitize(htmlFragment);

            // Assert
            string expected = "<img>";
            Assert.Equal(expected, actual, ignoreCase: true);
        }

        /// <summary>
        /// A test for Xss vector with BGSound
        /// Example <!-- <BGSOUND SRC="javascript:alert('XSS');"> -->
        /// </summary>
        [Fact]
        public void BGSoundXSSTest()
        {
            // Arrange
            var sanitizer = Sanitizer;


            // Act
            string htmlFragment = "<BGSOUND SRC=\"javascript:alert('XSS');\">";
            string actual = sanitizer.Sanitize(htmlFragment);

            // Assert
            string expected = "";
            Assert.Equal(expected, actual, ignoreCase: true);
        }

        /// <summary>
        /// A test for BR with Javascript Include
        /// Example <!-- <BR SIZE="&{alert('XSS')}"> -->
        /// </summary>
        [Fact]
        public void BRJavascriptIncludeXSSTest()
        {
            // Arrange
            var sanitizer = Sanitizer;


            // Act
            string htmlFragment = "<BR SIZE=\"&{alert('XSS')}\">";
            string actual = sanitizer.Sanitize(htmlFragment);

            // Assert
            string expected = "<BR>";
            Assert.Equal(expected, actual, ignoreCase: true);
        }

        /// <summary>
        /// A test for P with url in style
        /// Example <!-- <p STYLE="behavior: url(www.ha.ckers.org);"> -->
        /// </summary>
        [Fact]
        public void PWithUrlInStyleXSSTest()
        {
            // Arrange
            var sanitizer = Sanitizer;


            // Act
            string htmlFragment = "<p STYLE=\"behavior: url(www.ha.ckers.org);\">";
            string actual = sanitizer.Sanitize(htmlFragment);

            // Assert
            // intentionally keep it failing to get notice when reviewing unit tests so can disucss
            string expected = "<p></p>";
            Assert.Equal(expected, actual, ignoreCase: true);
        }

        /// <summary>
        /// A test for Image with vbscript
        /// Example <!-- <IMG SRC='vbscript:msgbox("XSS")'> -->
        /// </summary>
        [Fact]
        public void ImageWithVBScriptXSSTest()
        {
            // Arrange
            var sanitizer = Sanitizer;


            // Act
            string htmlFragment = "<IMG SRC='vbscript:msgbox(\"XSS\")'>";
            string actual = sanitizer.Sanitize(htmlFragment);

            // Assert
            string expected = "<img>";
            Assert.Equal(expected, actual, ignoreCase: true);
        }

        /// <summary>
        /// A test for Image with Mocha
        /// Example <!-- <IMG SRC="mocha:[code]"> -->
        /// </summary>
        [Fact]
        public void ImageWithMochaXSSTest()
        {
            // Arrange
            var sanitizer = Sanitizer;


            // Act
            string htmlFragment = "<IMG SRC=\"mocha:[code]\">";
            string actual = sanitizer.Sanitize(htmlFragment);

            // Assert
            string expected = "<img>";
            Assert.Equal(expected, actual, ignoreCase: true);
        }

        /// <summary>
        /// A test for Image with Livescript
        /// Example <!-- <IMG SRC="Livescript:[code]"> -->
        /// </summary>
        [Fact]
        public void ImageWithLivescriptXSSTest()
        {
            // Arrange
            var sanitizer = Sanitizer;


            // Act
            string htmlFragment = "<IMG SRC=\"Livescript:[code]\">";
            string actual = sanitizer.Sanitize(htmlFragment);

            // Assert
            string expected = "<img>";
            Assert.Equal(expected, actual, ignoreCase: true);
        }

        /// <summary>
        /// A test for Iframe
        /// Example <!-- <IFRAME SRC="javascript:alert('XSS');"></IFRAME> -->
        /// </summary>
        [Fact]
        public void IframeXSSTest()
        {
            // Arrange
            var sanitizer = Sanitizer;


            // Act
            string htmlFragment = "<IFRAME SRC=\"javascript:alert('XSS');\"></IFRAME>";
            string actual = sanitizer.Sanitize(htmlFragment);

            // Assert
            string expected = "";
            Assert.Equal(expected, actual, ignoreCase: true);
        }

        /// <summary>
        /// A test for Frame
        /// Example <!-- <FRAMESET><FRAME SRC="javascript:alert('XSS');"></FRAMESET> -->
        /// </summary>
        [Fact]
        public void FrameXSSTest()
        {
            // Arrange
            var sanitizer = Sanitizer;


            // Act
            string htmlFragment = "<FRAMESET><FRAME SRC=\"javascript:alert('XSS');\"></FRAMESET>";
            string actual = sanitizer.Sanitize(htmlFragment);

            // Assert
            string expected = "";
            Assert.Equal(expected, actual, ignoreCase: true);
        }

        /// <summary>
        /// A test for Table
        /// Example <!-- <TABLE BACKGROUND="javascript:alert('XSS')"> -->
        /// </summary>
        [Fact]
        public void TableXSSTest()
        {
            // Arrange
            var sanitizer = Sanitizer;


            // Act
            string htmlFragment = "<TABLE BACKGROUND=\"javascript:alert('XSS')\">";
            string actual = sanitizer.Sanitize(htmlFragment);

            // Assert
            string expected = "<table></table>";
            Assert.Equal(expected, actual, ignoreCase: true);
        }

        /// <summary>
        /// A test for TD
        /// Example <!-- <TABLE><TD BACKGROUND="javascript:alert('XSS')"> -->
        /// </summary>
        [Fact]
        public void TDXSSTest()
        {
            // Arrange
            var sanitizer = Sanitizer;


            // Act
            string htmlFragment = "<TABLE><TD BACKGROUND=\"javascript:alert('XSS')\">";
            string actual = sanitizer.Sanitize(htmlFragment);

            // Assert
            string expected = "<table><tbody><tr><td></td></tr></tbody></table>";
            Assert.Equal(expected, actual, ignoreCase: true);
        }

        /// <summary>
        /// A test for Div Background Image
        /// Example <!-- <DIV STYLE="background-image: url(javascript:alert('XSS'))"> -->
        /// </summary>
        [Fact]
        public void DivBackgroundImageXSSTest()
        {
            // Arrange
            var sanitizer = Sanitizer;


            // Act
            string htmlFragment = "<DIV STYLE=\"background-image: url(javascript:alert('XSS'))\">";
            string actual = sanitizer.Sanitize(htmlFragment);

            // Assert
            string expected = "<div></div>";
            Assert.Equal(expected, actual, ignoreCase: true);
        }

        /// <summary>
        /// A test for Div Background Image  with unicoded XSS
        /// Example <!-- <DIV STYLE="background-image:\0075\0072\006C\0028'\006a\0061\0076\0061\0073\0063\0072\0069\0070\0074\003a\0061\006c\0065\0072\0074\0028.1027\0058.1053\0053\0027\0029'\0029"> -->
        /// </summary>
        [Fact]
        public void DivBackgroundImageWithUnicodedXSSTest()
        {
            // Arrange
            var sanitizer = Sanitizer;


            // Act
            string htmlFragment = @"<DIV STYLE=""background-image:\0075\0072\006C\0028'\006a\0061\0076\0061\0073\0063\0072\0069\0070\0074\003a\0061\006c\0065\0072\0074\0028\0027\0058\0053\0053\0027\0029'\0029"">";
            string actual = sanitizer.Sanitize(htmlFragment);

            // Assert
            string expected = "<div></div>";
            Assert.Equal(expected, actual, ignoreCase: true);
        }

        /// <summary>
        /// A test for Div Background Image  with extra characters
        /// Example <!-- <DIV STYLE="background-image: url(&#1;javascript:alert('XSS'))"> -->
        /// </summary>
        [Fact]
        public void DivBackgroundImageWithExtraCharactersXSSTest()
        {
            // Arrange
            var sanitizer = Sanitizer;


            // Act
            string htmlFragment = "<DIV STYLE=\"background-image: url(&#1;javascript:alert('XSS'))\">";
            string actual = sanitizer.Sanitize(htmlFragment);

            // Assert
            string expected = "<div></div>";
            Assert.Equal(expected, actual, ignoreCase: true);
        }

        /// <summary>
        /// A test for DIV expression
        /// Example <!-- <DIV STYLE="width: expression(alert('XSS'));"> -->
        /// </summary>
        [Fact]
        public void DivExpressionXSSTest()
        {
            // Arrange
            var sanitizer = Sanitizer;


            // Act
            string htmlFragment = "<DIV STYLE=\"width: expression(alert('XSS'));\">";
            string actual = sanitizer.Sanitize(htmlFragment);

            // Assert
            string expected = "<div></div>";
            Assert.Equal(expected, actual, ignoreCase: true);
        }

        /// <summary>
        /// A test for Image with break up expression
        /// Example <!-- <IMG STYLE="xss:expr/*XSS*/ession(alert('XSS'))"> -->
        /// </summary>
        [Fact]
        public void ImageStyleExpressionXSSTest()
        {
            // Arrange
            var sanitizer = Sanitizer;


            // Act
            string htmlFragment = "<IMG STYLE=\"xss:expr/*XSS*/ession(alert('XSS'))\">";
            string actual = sanitizer.Sanitize(htmlFragment);

            // Assert
            string expected = "<img>";
            Assert.Equal(expected, actual, ignoreCase: true);
        }

        /// <summary>
        /// A test for AnchorTag with break up expression
        /// Example <!-- exp/*<A STYLE='no\xss:noxss("*//*");xss:&#101;x&#x2F;*XSS*//*/*/pression(alert("XSS"))'> -->
        /// </summary>
        [Fact]
        public void AnchorTagStyleExpressionXSSTest()
        {
            // Arrange
            var sanitizer = Sanitizer;


            // Act
            string htmlFragment = "exp/*<A STYLE='no\\xss:noxss(\"*//*\");xss:&#101;x&#x2F;*XSS*//*/*/pression(alert(\"XSS\"))'>";
            string actual = sanitizer.Sanitize(htmlFragment);

            // Assert
            string expected = "exp/*<a></a>";
            Assert.Equal(expected, actual, ignoreCase: true);
        }

        /// <summary>
        /// A test for BaseTag
        /// Example <!-- <BASE HREF="javascript:alert('XSS');//"> -->
        /// </summary>
        [Fact]
        public void BaseTagXSSTest()
        {
            // Arrange
            var sanitizer = Sanitizer;


            // Act
            string htmlFragment = "<BASE HREF=\"javascript:alert('XSS');//\">";
            string actual = sanitizer.Sanitize(htmlFragment);

            // Assert
            string expected = "";
            Assert.Equal(expected, actual, ignoreCase: true);
        }

        /// <summary>
        /// A test for EMBEDTag
        /// Example <!-- <EMBED SRC="http://ha.ckers.org/xss.swf" AllowScriptAccess="always"></EMBED> -->
        /// </summary>
        [Fact]
        public void EmbedTagXSSTest()
        {
            // Arrange
            var sanitizer = Sanitizer;


            // Act
            string htmlFragment = "<EMBED SRC=\"http://ha.ckers.org/xss.swf\" AllowScriptAccess=\"always\"></EMBED>";
            string actual = sanitizer.Sanitize(htmlFragment);

            // Assert
            string expected = "";
            Assert.Equal(expected, actual, ignoreCase: true);
        }

        /// <summary>
        /// A test for EMBEDSVG
        /// Example <!-- <EMBED SRC="data:image/svg+xml;base64,PHN2ZyB4bWxuczpzdmc9Imh0dH A6Ly93d3cudzMub3JnLzIwMDAvc3ZnIiB4bWxucz0iaHR0cDovL3d3dy53My5vcmcv MjAwMC9zdmciIHhtbG5zOnhsaW5rPSJodHRwOi8vd3d3LnczLm9yZy8xOTk5L3hs aW5rIiB2ZXJzaW9uPSIxLjAiIHg9IjAiIHk9IjAiIHdpZHRoPSIxOTQiIGhlaWdodD0iMjAw IiBpZD0ieHNzIj48c2NyaXB0IHR5cGU9InRleHQvZWNtYXNjcmlwdCI+YWxlcnQoIlh TUyIpOzwvc2NyaXB0Pjwvc3ZnPg==" type="image/svg+xml" AllowScriptAccess="always"></EMBED> -->
        /// </summary>
        [Fact]
        public void EmbedSVGXSSTest()
        {
            // Arrange
            var sanitizer = Sanitizer;


            // Act
            string htmlFragment = "<EMBED SRC=\"data:image/svg+xml;base64,PHN2ZyB4bWxuczpzdmc9Imh0dH A6Ly93d3cudzMub3JnLzIwMDAvc3ZnIiB4bWxucz0iaHR0cDovL3d3dy53My5vcmcv MjAwMC9zdmciIHhtbG5zOnhsaW5rPSJodHRwOi8vd3d3LnczLm9yZy8xOTk5L3hs aW5rIiB2ZXJzaW9uPSIxLjAiIHg9IjAiIHk9IjAiIHdpZHRoPSIxOTQiIGhlaWdodD0iMjAw IiBpZD0ieHNzIj48c2NyaXB0IHR5cGU9InRleHQvZWNtYXNjcmlwdCI+YWxlcnQoIlh TUyIpOzwvc2NyaXB0Pjwvc3ZnPg==\" type=\"image/svg+xml\" AllowScriptAccess=\"always\"></EMBED>";
            string actual = sanitizer.Sanitize(htmlFragment);

            // Assert
            string expected = "";
            Assert.Equal(expected, actual, ignoreCase: true);
        }

        /// <summary>
        /// A test for XML namespace
        /// Example <!-- <HTML xmlns:xss>  <?import namespace="xss" implementation="http://ha.ckers.org/xss.htc">  <xss:xss>XSS</xss:xss></HTML> -->
        /// </summary>
        [Fact]
        public void XmlNamespaceXSSTest()
        {
            // Arrange
            var sanitizer = Sanitizer;


            // Act
            string htmlFragment = "<HTML xmlns:xss><?import namespace=\"xss\" implementation=\"http://ha.ckers.org/xss.htc\"><xss:xss>XSS</xss:xss></HTML>";
            string actual = sanitizer.Sanitize(htmlFragment);

            // Assert
            string expected = "";
            Assert.Equal(expected, actual, ignoreCase: true);
        }

        /// <summary>
        /// A test for XML with CData
        /// Example <!-- <XML ID=I><X><C><![CDATA[<IMG SRC="javas]]><![CDATA[cript:alert('XSS');">]]></C></X></xml><SPAN DATASRC=#I DATAFLD=C DATAFORMATAS=HTML></SPAN> -->
        /// </summary>
        [Fact]
        public void XmlWithCDataXSSTest()
        {
            // Arrange
            var sanitizer = Sanitizer;


            // Act
            string htmlFragment = "<XML ID=I><X><C><![CDATA[<IMG SRC=\"javas]]><![CDATA[cript:alert('XSS');\">]]></C></X></xml><SPAN DATASRC=#I DATAFLD=C DATAFORMATAS=HTML></SPAN>";
            string actual = sanitizer.Sanitize(htmlFragment);

            // Assert
            string expected = "<SPAN></SPAN>";
            Assert.Equal(expected, actual, ignoreCase: true);
        }

        /// <summary>
        /// A test for XML with Comment obfuscation
        /// </summary>
        [Fact]
        public void XmlWithCommentObfuscationXSSTest()
        {
            // Arrange
            var sanitizer = Sanitizer;


            // Act
            string htmlFragment = "<XML ID=\"xss\"><I><B>&lt;IMG SRC=\"javas<!-- -->cript:alert('XSS')\"&gt;</B></I></XML><SPAN DATASRC=\"#xss\" DATAFLD=\"B\" DATAFORMATAS=\"HTML\"></SPAN>";
            string actual = sanitizer.Sanitize(htmlFragment);

            // Assert
            string expected = "<SPAN></SPAN>";
            Assert.Equal(expected, actual, ignoreCase: true);
        }

        /// <summary>
        /// A test for XML with Embedded script
        /// Example <!-- <XML SRC="xsstest.xml" ID=I></XML><SPAN DATASRC=#I DATAFLD=C DATAFORMATAS=HTML></SPAN> -->
        /// </summary>
        [Fact]
        public void XmlWithEmbeddedScriptXSSTest()
        {
            // Arrange
            var sanitizer = Sanitizer;


            // Act
            string htmlFragment = "<XML SRC=\"xsstest.xml\" ID=I></XML><SPAN DATASRC=#I DATAFLD=C DATAFORMATAS=HTML></SPAN>";
            string actual = sanitizer.Sanitize(htmlFragment);

            // Assert
            string expected = "<SPAN></SPAN>";
            Assert.Equal(expected, actual, ignoreCase: true);
        }

        /// <summary>
        /// A test for Html + Time
        /// Example <!-- <HTML><BODY><?xml:namespace prefix="t" ns="urn:schemas-microsoft-com:time"><?import namespace="t" implementation="#default#time2"><t:set attributeName="innerHTML" to="XSS&lt;SCRIPT DEFER&gt;alert(&quot;XSS&quot;)&lt;/SCRIPT&gt;"></BODY></HTML> -->
        /// </summary>
        [Fact]
        public void HtmlPlusTimeXSSTest()
        {
            // Arrange
            var sanitizer = Sanitizer;


            // Act
            string htmlFragment = "<HTML><BODY><?xml:namespace prefix=\"t\" ns=\"urn:schemas-microsoft-com:time\"><?import namespace=\"t\" implementation=\"#default#time2\"><t:set attributeName=\"innerHTML\" to=\"XSS&lt;SCRIPT DEFER&gt;alert(&quot;XSS&quot;)&lt;/SCRIPT&gt;\"></BODY></HTML>";
            string actual = sanitizer.Sanitize(htmlFragment);

            // Assert
            string expected = "";
            Assert.Equal(expected, actual, ignoreCase: true);
        }

        /// <summary>
        /// A test for AnchorTag with javascript link location
        /// Example <!-- <A HREF="javascript:document.location='http://www.google.com/'">XSS</A> -->
        /// </summary>
        [Fact]
        public void AnchorTagJavascriptLinkLocationXSSTest()
        {
            // Arrange
            var sanitizer = Sanitizer;


            // Act
            string htmlFragment = "<A HREF=\"javascript:document.location='http://www.google.com/'\">XSS</A>";
            string actual = sanitizer.Sanitize(htmlFragment);

            // Assert
            string expected = "<a>XSS</a>";
            Assert.Equal(expected, actual, ignoreCase: true);
        }

        /// <summary>
        /// A test for Div with no filter evasion
        /// Example <!-- <Div style="background-color: http://www.codeplex.com?url=<SCRIPT SRC=http://ha.ckers.org/xss.js></SCRIPT>"> -->
        /// </summary>
        [Fact]
        public void DivNoFilterEvasionXSSTest()
        {
            // Arrange
            var sanitizer = Sanitizer;


            // Act
            string htmlFragment = "<Div style=\"background-color: http://www.codeplex.com?url=<SCRIPT SRC=http://ha.ckers.org/xss.js></SCRIPT>\">";
            string actual = sanitizer.Sanitize(htmlFragment);

            // Assert
            string expected = "<div></div>";
            Assert.Equal(expected, actual, ignoreCase: true);
        }

        /// <summary>
        /// A test for Div with style expression and no filter evasion
        /// Example <!-- <Div style="background-color: expression(<SCRIPT SRC=http://ha.ckers.org/xss.js></SCRIPT>)"> -->
        /// </summary>
        [Fact]
        public void DivStyleExpressionNoFilterEvasionXSSTest()
        {
            // Arrange
            var sanitizer = Sanitizer;


            // Act
            string htmlFragment = "<Div style=\"background-color: expression(<SCRIPT SRC=http://ha.ckers.org/xss.js></SCRIPT>)\">";
            string actual = sanitizer.Sanitize(htmlFragment);

            // Assert
            string expected = "<div></div>";
            Assert.Equal(expected, actual, ignoreCase: true);
        }

        /// <summary>
        /// A test for AnchorTag with non alpha non digit xss
        /// Example <!-- <A HREF="http://www.codeplex.com?url=<SCRIPT/XSS SRC="http://ha.ckers.org/xss.js"></SCRIPT>">XSS</A> -->
        /// </summary>
        [Fact]
        public void AnchorTagNonAlphaNonDigitXSSTest()
        {
            // Arrange
            var sanitizer = Sanitizer;


            // Act
            string htmlFragment = "<A HREF=\"http://www.codeplex.com?url=<SCRIPT/XSS SRC=\"http://ha.ckers.org/xss.js\"></SCRIPT>\">XSS</A>";
            string actual = sanitizer.Sanitize(htmlFragment);

            // Assert
            string expected = "<a href=\"http://www.codeplex.com?url=&lt;SCRIPT/XSS SRC=\">\"&gt;XSS</a>";
            Assert.Equal(expected, actual, ignoreCase: true);
        }

        /// <summary>
        /// A test for Div with non alpha non digit xss
        /// Example <!-- <Div style="background-color: http://www.codeplex.com?url=<SCRIPT/XSS SRC=http://ha.ckers.org/xss.js></SCRIPT>"> -->
        /// </summary>
        [Fact]
        public void DivNonAlphaNonDigitXSSTest()
        {
            // Arrange
            var sanitizer = Sanitizer;


            // Act
            string htmlFragment = "<Div style=\"background-color: http://www.codeplex.com?url=<SCRIPT/XSS SRC=\"http://ha.ckers.org/xss.js\"></SCRIPT>\">";
            string actual = sanitizer.Sanitize(htmlFragment);

            // Assert
            string expected = "<div>\"&gt;</div>";
            Assert.Equal(expected, actual, ignoreCase: true);
        }

        /// <summary>
        /// A test for Div with style expression and non alpha non digit xss
        /// Example <!-- <Div style="background-color: expression(<SCRIPT/XSS SRC="http://ha.ckers.org/xss.js"></SCRIPT>)"> -->
        /// </summary>
        [Fact]
        public void DivStyleExpressionNonAlphaNonDigitXSSTest()
        {
            // Arrange
            var sanitizer = Sanitizer;


            // Act
            string htmlFragment = "<Div style=\"background-color: expression(<SCRIPT/XSS SRC=\"http://ha.ckers.org/xss.js\"></SCRIPT>)\">";
            string actual = sanitizer.Sanitize(htmlFragment);

            // Assert
            string expected = "<div>)\"&gt;</div>";
            Assert.Equal(expected, actual, ignoreCase: true);
        }

        /// <summary>
        /// A test for Div with non alpha non digit part 3 xss
        /// Example <!-- <Div style="background-color: http://www.codeplex.com?url=<SCRIPT/SRC=http://ha.ckers.org/xss.js></SCRIPT>"> -->
        /// </summary>
        [Fact]
        public void DivNonAlphaNonDigit3XSSTest()
        {
            // Arrange
            var sanitizer = Sanitizer;


            // Act
            string htmlFragment = "<Div style=\"background-color: http://www.codeplex.com?url=<SCRIPT/SRC=\"http://ha.ckers.org/xss.js\"></SCRIPT>\">";
            string actual = sanitizer.Sanitize(htmlFragment);

            // Assert
            string expected = "<div>\"&gt;</div>";
            Assert.Equal(expected, actual, ignoreCase: true);
        }

        /// <summary>
        /// A test for Div with style expression and non alpha non digit part 3 xss
        /// Example <!-- <Div style="background-color: expression(<SCRIPT/SRC="http://ha.ckers.org/xss.js"></SCRIPT>)"> -->
        /// </summary>
        [Fact]
        public void DivStyleExpressionNonAlphaNonDigit3XSSTest()
        {
            // Arrange
            var sanitizer = Sanitizer;


            // Act
            string htmlFragment = "<Div style=\"background-color: expression(<SCRIPT/SRC=\"http://ha.ckers.org/xss.js\"></SCRIPT>)\">";
            string actual = sanitizer.Sanitize(htmlFragment);

            // Assert
            string expected = "<div>)\"&gt;</div>";
            Assert.Equal(expected, actual, ignoreCase: true);
        }

        /// <summary>
        /// A test for AnchorTag with Extraneous open brackets xss
        /// Example <!-- <A HREF="http://www.codeplex.com?url=<<SCRIPT>alert("XSS");//<</SCRIPT>">XSS</A> -->
        /// </summary>
        [Fact]
        public void AnchorTagExtraneousOpenBracketsXSSTest()
        {
            // Arrange
            var sanitizer = Sanitizer;


            // Act
            string htmlFragment = "<A HREF=\"http://www.codeplex.com?url=<<SCRIPT>alert(\"XSS\");//<</SCRIPT>\">XSS</A>";
            string actual = sanitizer.Sanitize(htmlFragment);

            // Assert
            string expected = "<a href=\"http://www.codeplex.com?url=&lt;&lt;SCRIPT&gt;alert(\">\"&gt;XSS</a>";
            Assert.Equal(expected, actual, ignoreCase: true);
        }

        /// <summary>
        /// A test for Div with Extraneous open brackets xss
        /// Example <!-- <Div style="background-color: http://www.codeplex.com?url=<<SCRIPT>alert("XSS");//<</SCRIPT>"> -->
        /// </summary>
        [Fact]
        public void DivExtraneousOpenBracketsXSSTest()
        {
            // Arrange
            var sanitizer = Sanitizer;


            // Act
            string htmlFragment = "<Div style=\"background-color: http://www.codeplex.com?url=<<SCRIPT>alert(\"XSS\");//<</SCRIPT>\">";
            string actual = sanitizer.Sanitize(htmlFragment);

            // Assert
            string expected = "<div>\"&gt;</div>";
            Assert.Equal(expected, actual, ignoreCase: true);
        }

        /// <summary>
        /// A test for Div with style expression and Extraneous open brackets xss
        /// Example <!-- <Div style="background-color: expression(<<SCRIPT>alert("XSS");//<</SCRIPT>)"> -->
        /// </summary>
        [Fact]
        public void DivStyleExpressionExtraneousOpenBracketsXSSTest()
        {
            // Arrange
            var sanitizer = Sanitizer;

            // Act
            string htmlFragment = "<Div style=\"background-color: expression(<<SCRIPT>alert(\"XSS\");//<</SCRIPT>)\">";
            string actual = sanitizer.Sanitize(htmlFragment);

            // Assert
            string expected = "<div>)\"&gt;</div>";
            Assert.Equal(expected, actual, ignoreCase: true);
        }

        /// <summary>
        /// A test for Div with No closing script tags xss
        /// Example <!-- <Div style="background-color: http://www.codeplex.com?url=<SCRIPT SRC=http://ha.ckers.org/xss.js?<B>"> -->
        /// </summary>
        [Fact]
        public void DivNoClosingScriptTagsXSSTest()
        {
            // Arrange
            var sanitizer = Sanitizer;


            // Act
            string htmlFragment = "<Div style=\"background-color: http://www.codeplex.com?url=<SCRIPT SRC=http://ha.ckers.org/xss.js?<B>\">";
            string actual = sanitizer.Sanitize(htmlFragment);

            // Assert
            string expected = "<div></div>";
            Assert.Equal(expected, actual, ignoreCase: true);
        }

        /// <summary>
        /// A test for Div with style expression and No closing script tags xss
        /// Example <!-- <Div style="background-color: expression(<SCRIPT SRC=http://ha.ckers.org/xss.js?<B>)"> -->
        /// </summary>
        [Fact]
        public void DivStyleExpressionNoClosingScriptTagsXSSTest()
        {
            // Arrange
            var sanitizer = Sanitizer;


            // Act
            string htmlFragment = "<Div style=\"background-color: expression(<SCRIPT SRC=http://ha.ckers.org/xss.js?<B>)\">";
            string actual = sanitizer.Sanitize(htmlFragment);

            // Assert
            string expected = "<div></div>";
            Assert.Equal(expected, actual, ignoreCase: true);
        }

        /// <summary>
        /// A test for AnchorTag with Protocol resolution in script tags xss
        /// Example <!-- <A HREF="http://www.codeplex.com?url=<SCRIPT SRC=//ha.ckers.org/.j>">XSS</A> -->
        /// </summary>
        [Fact]
        public void AnchorTagProtocolResolutionScriptXSSTest()
        {
            // Arrange
            var sanitizer = Sanitizer;


            // Act
            string htmlFragment = "<A HREF=\"http://www.codeplex.com?url=<SCRIPT SRC=//ha.ckers.org/.j>\">XSS</A>";
            string actual = sanitizer.Sanitize(htmlFragment);

            // Assert
            string expected = "<a href=\"http://www.codeplex.com?url=&lt;SCRIPT SRC=//ha.ckers.org/.j&gt;\">XSS</a>";
            Assert.Equal(expected, actual, ignoreCase: true);
        }

        /// <summary>
        /// A test for Div with Protocol resolution in script tags xss
        /// Example <!-- <Div style="background-color: http://www.codeplex.com?url=<SCRIPT SRC=//ha.ckers.org/.j>"> -->
        /// </summary>
        [Fact]
        public void DivProtocolResolutionScriptXSSTest()
        {
            // Arrange
            var sanitizer = Sanitizer;


            // Act
            string htmlFragment = "<Div style=\"background-color: http://www.codeplex.com?url=<SCRIPT SRC=//ha.ckers.org/.j>\">";
            string actual = sanitizer.Sanitize(htmlFragment);

            // Assert
            string expected = "<div></div>";
            Assert.Equal(expected, actual, ignoreCase: true);
        }

        /// <summary>
        /// A test for Div with style expression and Protocol resolution in script tags xss
        /// Example <!-- <Div style="background-color: expression(<SCRIPT SRC=//ha.ckers.org/.j>)"> -->
        /// </summary>
        [Fact]
        public void DivStyleExpressionProtocolResolutionScriptXSSTest()
        {
            // Arrange
            var sanitizer = Sanitizer;


            // Act
            string htmlFragment = "<Div style=\"background-color: expression(<SCRIPT SRC=//ha.ckers.org/.j>)\">";
            string actual = sanitizer.Sanitize(htmlFragment);

            // Assert
            string expected = "<div></div>";
            Assert.Equal(expected, actual, ignoreCase: true);
        }

        /// <summary>
        /// A test for AnchorTag with no single quotes or double quotes or semicolons xss
        /// Example <!-- <A HREF="http://www.codeplex.com?url=<SCRIPT>a=/XSS/alert(a.source)</SCRIPT>">XSS</A> -->
        /// </summary>
        [Fact]
        public void AnchorTagNoQuotesXSSTest()
        {
            // Arrange
            var sanitizer = Sanitizer;


            // Act
            string htmlFragment = "<A HREF=\"http://www.codeplex.com?url=<SCRIPT>a=/XSS/alert(a.source)</SCRIPT>\">XSS</A>";
            string actual = sanitizer.Sanitize(htmlFragment);

            // Assert
            string expected = "<a href=\"http://www.codeplex.com?url=&lt;SCRIPT&gt;a=/XSS/alert(a.source)&lt;/SCRIPT&gt;\">XSS</a>";
            Assert.Equal(expected, actual, ignoreCase: true);
        }

        /// <summary>
        /// A test for Div with no single quotes or double quotes or semicolons xss
        /// Example <!-- <Div style="background-color: http://www.codeplex.com?url=<SCRIPT>a=/XSS/alert(a.source)</SCRIPT>"> -->
        /// </summary>
        [Fact]
        public void DivNoQuotesXSSTest()
        {
            // Arrange
            var sanitizer = Sanitizer;


            // Act
            string htmlFragment = "<Div style=\"background-color: http://www.codeplex.com?url=<SCRIPT>a=/XSS/alert(a.source)</SCRIPT>\">";
            string actual = sanitizer.Sanitize(htmlFragment);

            // Assert
            string expected = "<div></div>";
            Assert.Equal(expected, actual, ignoreCase: true);
        }

        /// <summary>
        /// A test for Div with style expression and no single quotes or double quotes or semicolons xss
        /// Example <!-- <Div style="background-color: expression(<SCRIPT>a=/XSS/alert(a.source)</SCRIPT>)"> -->
        /// </summary>
        [Fact]
        public void DivStyleExpressionNoQuotesXSSTest()
        {
            // Arrange
            var sanitizer = Sanitizer;


            // Act
            string htmlFragment = "<Div style=\"background-color: expression(<SCRIPT>a=/XSS/alert(a.source)</SCRIPT>)\">";
            string actual = sanitizer.Sanitize(htmlFragment);

            // Assert
            string expected = "<div></div>";
            Assert.Equal(expected, actual, ignoreCase: true);
        }

        /// <summary>
        /// A test for AnchorTag with US-ASCII encoding xss
        /// Example <!-- <A HREF="http://www.codeplex.com?url=¼script¾alert(¢XSS¢)¼/script¾">XSS</A> -->
        /// </summary>
        [Fact]
        public void AnchorTagUSASCIIEncodingXSSTest()
        {
            // Arrange
            var sanitizer = Sanitizer;


            // Act
            string htmlFragment = "<A HREF=\"http://www.codeplex.com?url=¼script¾alert(¢XSS¢)¼/script¾\">XSS</A>";
            string actual = sanitizer.Sanitize(htmlFragment);

            // Assert
            string expected = "<a href=\"http://www.codeplex.com?url=¼script¾alert(¢XSS¢)¼/script¾\">XSS</a>";
            Assert.Equal(expected, actual, ignoreCase: true);
        }

        /// <summary>
        /// A test for AnchorTag with Downlevel-Hidden block xss
        /// </summary>
        [Fact]
        public void AnchorTagDownlevelHiddenBlockXSSTest()
        {
            // Arrange
            var sanitizer = Sanitizer;


            // Act
            string htmlFragment = "<A HREF=\"http://www.codeplex.com?url=<!--[if gte IE 4]><SCRIPT>alert('XSS');</SCRIPT><![endif]-->\">XSS</A>";
            string actual = sanitizer.Sanitize(htmlFragment);

            // Assert
            string expected = "<a href=\"http://www.codeplex.com?url=&lt;!--[if gte IE 4]&gt;&lt;SCRIPT&gt;alert('XSS');&lt;/SCRIPT&gt;&lt;![endif]--&gt;\">XSS</a>";

            try
            {
                Assert.Equal(expected, actual, ignoreCase: true);
            }
#pragma warning disable CA1031 // Do not catch general exception types
            catch (Exception)
            {

                //in .net 3.5 there is a bug with URI, and so this test would otherwise fail on .net 3.5 in Appveyor / nunit:
                //http://help.appveyor.com/discussions/problems/1625-nunit-not-picking-up-net-framework-version
                //http://stackoverflow.com/questions/27019061/forcing-nunit-console-runner-to-use-clr-4-5
                string expectedNet35 = @"<a href=""http://www.codeplex.com/?url=%3C!--%5Bif%20gte%20IE%204%5D%3E%3CSCRIPT%3Ealert('XSS');%3C/SCRIPT%3E%3C!%5Bendif%5D--%3E"">XSS</a>";


                Assert.Equal(expectedNet35, actual, ignoreCase: true);
            }
#pragma warning restore CA1031 // Do not catch general exception types
        }

        /// <summary>
        /// A test for Div with Downlevel-Hidden block xss
        /// </summary>
        [Fact]
        public void DivDownlevelHiddenBlockXSSTest()
        {
            // Arrange
            var sanitizer = Sanitizer;


            // Act
            string htmlFragment = "<Div style=\"background-color: http://www.codeplex.com?url=<!--[if gte IE 4]><SCRIPT>alert('XSS');</SCRIPT><![endif]-->\">";
            string actual = sanitizer.Sanitize(htmlFragment);

            // Assert
            string expected = @"<div></div>";
            Assert.Equal(expected, actual, ignoreCase: true);
        }

        /// <summary>
        /// A test for AnchorTag with Html Quotes Encapsulation 1 xss
        /// Example <!-- <A HREF="http://www.codeplex.com?url=<SCRIPT a=">" SRC="http://ha.ckers.org/xss.js"></SCRIPT>">XSS</A> -->
        /// </summary>
        [Fact]
        public void AnchorTagHtmlQuotesEncapsulation1XSSTest()
        {
            // Arrange
            var sanitizer = Sanitizer;


            // Act
            string htmlFragment = "<A HREF=\"http://www.codeplex.com?url=<SCRIPT a=\">\" SRC=\"http://ha.ckers.org/xss.js\"></SCRIPT>\">XSS</A>";
            string actual = sanitizer.Sanitize(htmlFragment);

            // Assert
            string expected = "<a href=\"http://www.codeplex.com?url=&lt;SCRIPT a=\">\" SRC=\"http://ha.ckers.org/xss.js\"&gt;\"&gt;XSS</a>";
            Assert.Equal(expected, actual, ignoreCase: true);
        }

        /// <summary>
        /// A test for Div with Html Quotes Encapsulation 1 xss
        /// Example <!-- <Div style="background-color: http://www.codeplex.com?url=<SCRIPT a=">" SRC="http://ha.ckers.org/xss.js"></SCRIPT>"> -->
        /// </summary>
        [Fact]
        public void DivHtmlQuotesEncapsulation1XSSTest()
        {
            // Arrange
            var sanitizer = Sanitizer;


            // Act
            string htmlFragment = "<Div style=\"background-color: http://www.codeplex.com?url=<SCRIPT a=\">\" SRC=\"http://ha.ckers.org/xss.js\"></SCRIPT>\">";
            string actual = sanitizer.Sanitize(htmlFragment);

            // Assert
            string expected = "<div>\" SRC=\"http://ha.ckers.org/xss.js\"&gt;\"&gt;</div>";
            Assert.Equal(expected, actual, ignoreCase: true);
        }

        /// <summary>
        /// A test for various legal fragments
        /// </summary>
        [Fact]
        public void LegalTest()
        {
            // Arrange
            var sanitizer = Sanitizer;

            // Act
            string htmlFragment = "<div style=\"background-color: test\">";
            string actual = sanitizer.Sanitize(htmlFragment);

            // Assert
            string expected = "<div></div>";
            Assert.Equal(expected, actual, ignoreCase: true);
        }

        /// <summary>
        /// More tests for legal fragments.
        /// </summary>
        [Fact]
        public void MoreLegalTest()
        {
            // Arrange
            var sanitizer = Sanitizer;

            // Act
            string htmlFragment = "<div style=\"background-color: test;\">Test<img src=\"http://www.example.com/test.gif\" style=\"background-image: url(http://www.example.com/bg.jpg); margin: 10px\"></div>";
            string actual = sanitizer.Sanitize(htmlFragment);

            // Assert
            string expected = "<div>Test<img src=\"http://www.example.com/test.gif\" style=\"background-image: url(&quot;http://www.example.com/bg.jpg&quot;); margin: 10px\"></div>";
            Assert.Equal(expected, actual, ignoreCase: true);
        }

        /// <summary>
        /// Misc tests.
        /// </summary>
        [Fact]
        public void MiscTest()
        {
            var sanitizer = Sanitizer;

            var html = @"<SCRIPT/SRC=""http://ha.ckers.org/xss.js""></SCRIPT>";
            var actual = sanitizer.Sanitize(html);
            var expected = "";
            Assert.Equal(expected, actual, ignoreCase: true);

            html = @"<DIV STYLE=""padding: &#49;px; mar/*xss*/gin: ex/*XSS*/pression(alert('xss')); background-image:\0075\0072\006C\0028\0022\006a\0061\0076\0061\0073\0063\0072\0069\0070\0074\003a\0061\006c\0065\0072\0074\0028\0027\0058\0053\0053\0027\0029\0022\0029"">";
            actual = sanitizer.Sanitize(html);
            expected = @"<div style=""padding: 1px""></div>";
            Assert.Equal(expected, actual, ignoreCase: true);

            html = @"<!--[if gte IE 4]><SCRIPT>alert('XSS');</SCRIPT><![endif]--><!-- Comment -->";
            actual = sanitizer.Sanitize(html);
            expected = "";
            Assert.Equal(expected, actual, ignoreCase: true);

            html = @"<STYLE>@im\port'\ja\vasc\ript:alert(""XSS"")';</STYLE>";
            actual = sanitizer.Sanitize(html);
            expected = "";
            Assert.Equal(expected, actual, ignoreCase: true);

            html = @"<div onload!#$%&()*~+-_.,:;?@[/|\]^`=alert(""XSS"")>";
            actual = sanitizer.Sanitize(html);
            expected = "<div></div>";
            Assert.Equal(expected, actual, ignoreCase: true);

            html = @"<SCRIPT/XSS SRC=""http://ha.ckers.org/xss.js""></SCRIPT>";
            actual = sanitizer.Sanitize(html);
            expected = "";
            Assert.Equal(expected, actual, ignoreCase: true);

            html = "<IMG SRC=javascript:alert(\"XSS\")>\"";
            actual = sanitizer.Sanitize(html);
            expected = "<img>\"";
            Assert.Equal(expected, actual, ignoreCase: true);

            html = "<IMG SRC=java\0script:alert(\"XSS\")>\"";
            actual = sanitizer.Sanitize(html);
            expected = "<img>\"";
            Assert.Equal(expected, actual, ignoreCase: true);

            html = @"<IMG SRC=""jav&#x0D;ascript:alert('XSS');"">";
            actual = sanitizer.Sanitize(html);
            expected = "<img>";
            Assert.Equal(expected, actual, ignoreCase: true);

            html = @"<IMG SRC=""jav&#x0A;ascript:alert('XSS');"">";
            actual = sanitizer.Sanitize(html);
            expected = "<img>";
            Assert.Equal(expected, actual, ignoreCase: true);

            html = @"<IMG SRC=""jav&#x09;ascript:alert('XSS');"">";
            actual = sanitizer.Sanitize(html);
            expected = "<img>";
            Assert.Equal(expected, actual, ignoreCase: true);

            html = @"<div style=""background-color: red""><sCRipt>hallo</scripT></div><a href=""#"">Test</a>";
            actual = sanitizer.Sanitize(html);
            expected = @"<div style=""background-color: rgba(255, 0, 0, 1)""></div><a href=""#"">Test</a>";
            Assert.Equal(expected, actual, ignoreCase: true);

            html = @"<IMG SRC=""jav	ascript:alert('XSS');"">";
            actual = sanitizer.Sanitize(html);
            expected = "<img>";
            Assert.Equal(expected, actual, ignoreCase: true);

            html = @"<IMG SRC="" &#14;  javascript:alert('XSS');"">";
            actual = sanitizer.Sanitize(html);
            expected = "<img>";
            Assert.Equal(expected, actual, ignoreCase: true);

            html = @"<IMG SRC=&#106;&#97;&#118;&#97;&#115;&#99;&#114;&#105;&#112;&#116;&#58;&#97;&#108;&#101;&#114;&#116;&#40;&#39;&#88;&#83;&#83;&#39;&#41;>";
            actual = sanitizer.Sanitize(html);
            expected = "<img>";
            Assert.Equal(expected, actual, ignoreCase: true);

            html = @"<IMG SRC=&#0000106&#0000097&#0000118&#0000097&#0000115&#0000099&#0000114&#0000105&#0000112&#0000116&#0000058&#0000097&#0000108&#0000101&#0000114&#0000116&#0000040&#0000039&#0000088&#0000083&#0000083&#0000039&#0000041>";
            actual = sanitizer.Sanitize(html);
            expected = "<img>";
            Assert.Equal(expected, actual, ignoreCase: true);

            html = @"<IMG SRC=&#x6A&#x61&#x76&#x61&#x73&#x63&#x72&#x69&#x70&#x74&#x3A&#x61&#x6C&#x65&#x72&#x74&#x28&#x27&#x58&#x53&#x53&#x27&#x29>";
            actual = sanitizer.Sanitize(html);
            expected = "<img>";
            Assert.Equal(expected, actual, ignoreCase: true);

            html = "<script>alert('xss')</script><div onload=\"alert('xss')\" style=\"background-color: red\">Test<img src=\"test.gif\" style=\"background-image: url(javascript:alert('xss')); margin: 10px\"></div>";
            actual = sanitizer.Sanitize(html, "http://www.example.com");
            expected = @"<div style=""background-color: rgba(255, 0, 0, 1)"">Test<img src=""http://www.example.com/test.gif"" style=""margin: 10px""></div>";
            Assert.Equal(expected, actual, ignoreCase: true);
        }

        /// <summary>
        /// Tests disallowed tags.
        /// </summary>
        [Fact]
        public void DisallowedTagTest()
        {
            var sanitizer = Sanitizer;

            var html = @"<bla>Hallo</bla>";
            var actual = sanitizer.Sanitize(html);
            var expected = "";
            Assert.Equal(expected, actual, ignoreCase: true);
        }

        /// <summary>
        /// Tests disallowed HTML attributes.
        /// </summary>
        [Fact]
        public void DisallowedAttributeTest()
        {
            var sanitizer = Sanitizer;

            var html = @"<div bla=""test"">Test</div>";
            var actual = sanitizer.Sanitize(html);
            var expected = @"<div>Test</div>";
            Assert.Equal(expected, actual, ignoreCase: true);
        }

        /// <summary>
        /// Tests sanitization of attributes that contain a URL.
        /// </summary>
        [Fact]
        public void UrlAttributeTest()
        {
            var sanitizer = Sanitizer;

            var html = @"<a href=""mailto:test@example.com"">test</a>";
            var actual = sanitizer.Sanitize(html);
            var expected = @"<a>test</a>";
            Assert.Equal(expected, actual, ignoreCase: true);

            html = @"<a href=""http:xxx"">test</a>";
            actual = sanitizer.Sanitize(html);
            expected = @"<a href=""http:xxx"">test</a>";
            Assert.Equal(expected, actual, ignoreCase: true);

            html = @"<a href=""folder/file.jpg"">test</a>";
            actual = sanitizer.Sanitize(html, @"http://www.example.com");
            expected = @"<a href=""http://www.example.com/folder/file.jpg"">test</a>";
            Assert.Equal(expected, actual, ignoreCase: true);
        }

        /// <summary>
        /// Tests disallowed css properties.
        /// </summary>
        [Fact]
        public void DisallowedStyleTest()
        {
            var sanitizer = Sanitizer;

            var html = @"<div style=""margin: 8px; bla: 1px"">test</div>";
            var actual = sanitizer.Sanitize(html);
            var expected = @"<div style=""margin: 8px"">test</div>";
            Assert.Equal(expected, actual, ignoreCase: true);
        }

        /// <summary>
        /// Tests sanitization of URLs that are contained in CSS property values.
        /// </summary>
        [Fact]
        public void UrlStyleTest()
        {
            var sanitizer = Sanitizer;

            var html = @"<div style=""padding: 10px; background-image: url(mailto:test@example.com)""></div>";
            var actual = sanitizer.Sanitize(html);
            var expected = @"<div style=""padding: 10px""></div>";
            Assert.Equal(expected, actual, ignoreCase: true);

            html = @"<div style=""padding: 10px; background-image: url(folder/file.jpg)""></div>";
            actual = sanitizer.Sanitize(html, @"http://www.example.com");
            expected = @"<div style=""padding: 10px; background-image: url(&quot;http://www.example.com/folder/file.jpg&quot;)""></div>";
            Assert.Equal(expected, actual, ignoreCase: true);
        }

        // test below from http://genshi.edgewall.org/

        [Fact]
        public void SanitizeUnchangedTest()
        {
            var sanitizer = Sanitizer;
            var html = @"<a href=""#"">fo<br />o</a>";
            Assert.Equal(@"<a href=""#"">fo<br>o</a>", sanitizer.Sanitize(html), ignoreCase: true);

            html = @"<a href=""#with:colon"">foo</a>";
            Assert.Equal(html, sanitizer.Sanitize(html), ignoreCase: true);
        }

        [Fact]
        public void SanitizeEscapeTextTest()
        {
            var sanitizer = Sanitizer;
            var html = @"<a href=""#"">fo&amp;</a>";
            Assert.Equal(@"<a href=""#"">fo&amp;</a>", sanitizer.Sanitize(html), ignoreCase: true);

            html = @"<a href=""#"">&lt;foo&gt;</a>";
            Assert.Equal(@"<a href=""#"">&lt;foo&gt;</a>", sanitizer.Sanitize(html), ignoreCase: true);
        }

        [Fact]
        public void SanitizeEntityrefTextTest()
        {
            var sanitizer = Sanitizer;
            var html = @"<a href=""#"">fo&ouml;</a>";
            Assert.Equal(@"<a href=""#"">foö</a>", sanitizer.Sanitize(html), ignoreCase: true);
        }

        [Fact]
        public void SanitizeEscapeAttrTest()
        {
            var sanitizer = Sanitizer;
            var html = @"<div title=""&lt;foo&gt;""></div>";
            Assert.Equal(@"<div title=""&lt;foo&gt;""></div>", sanitizer.Sanitize(html), ignoreCase: true);
        }

        [Fact]
        public void SanitizeCloseEmptyTagTest()
        {
            var sanitizer = Sanitizer;
            var html = @"<a href=""#"">fo<br>o</a>";
            Assert.Equal(@"<a href=""#"">fo<br>o</a>", sanitizer.Sanitize(html), ignoreCase: true);
        }

        [Fact]
        public void SanitizeInvalidEntityTest()
        {
            var sanitizer = Sanitizer;
            var html = @"&junk;";
            Assert.Equal(@"&amp;junk;", sanitizer.Sanitize(html), ignoreCase: true);
        }

        [Fact]
        public void SanitizeRemoveScriptElemTest()
        {
            var sanitizer = Sanitizer;
            var html = @"<script>alert(""Foo"")</script>";
            Assert.Equal(@"", sanitizer.Sanitize(html), ignoreCase: true);
            html = @"<SCRIPT SRC=""http://example.com/""></SCRIPT>";
            Assert.Equal(@"", sanitizer.Sanitize(html), ignoreCase: true);
        }

        [Fact]
        public void SanitizeRemoveOnclickAttrTest()
        {
            var sanitizer = Sanitizer;
            var html = @"<div onclick=\'alert(""foo"")\' />";
            Assert.Equal(@"<div></div>", sanitizer.Sanitize(html), ignoreCase: true);
        }

        [Fact]
        public void SanitizeRemoveCommentsTest()
        {
            var sanitizer = Sanitizer;
            var html = @"<div><!-- conditional comment crap --></div>";
            Assert.Equal(@"<div></div>", sanitizer.Sanitize(html), ignoreCase: true);
        }

        [Fact]
        public void SanitizeRemoveStyleScriptsTest()
        {
            var sanitizer = Sanitizer;
            // Inline style with url() using javascript: scheme
            var html = @"<DIV STYLE='background-image: url(javascript:alert(""foo""))'>";
            Assert.Equal(@"<div></div>", sanitizer.Sanitize(html), ignoreCase: true);
            // Inline style with url() using javascript: scheme, using control char
            html = @"<DIV STYLE='background-image: url(&#1;javascript:alert(""foo""))'>";
            Assert.Equal(@"<div></div>", sanitizer.Sanitize(html), ignoreCase: true);
            // Inline style with url() using javascript: scheme, in quotes
            html = @"<DIV STYLE='background-image: url(""javascript:alert(foo)"")'>";
            Assert.Equal(@"<div></div>", sanitizer.Sanitize(html), ignoreCase: true);
            // IE expressions in CSS not allowed
            html = @"<DIV STYLE='width: expression(alert(""foo""));'>";
            Assert.Equal(@"<div></div>", sanitizer.Sanitize(html), ignoreCase: true);
            html = @"<DIV STYLE='width: e/**/xpression(alert(""foo""));'>";
            Assert.Equal(@"<div></div>", sanitizer.Sanitize(html), ignoreCase: true);
            html = @"<DIV STYLE='background-image: url(javascript:alert(""foo""));color: #fff'>";
            Assert.Equal(@"<div style=""color: rgba(255, 255, 255, 1)""></div>", sanitizer.Sanitize(html), ignoreCase: true);

            // Inline style with url() using javascript: scheme, using unicode
            // escapes
            html = @"<DIV STYLE='background-image: \75rl(javascript:alert(""foo""))'>";
            Assert.Equal(@"<div></div>", sanitizer.Sanitize(html), ignoreCase: true);
            html = @"<DIV STYLE='background-image: \000075rl(javascript:alert(""foo""))'>";
            Assert.Equal(@"<div></div>", sanitizer.Sanitize(html), ignoreCase: true);
            html = @"<DIV STYLE='background-image: \75 rl(javascript:alert(""foo""))'>";
            Assert.Equal(@"<div></div>", sanitizer.Sanitize(html), ignoreCase: true);
            html = @"<DIV STYLE='background-image: \000075 rl(javascript:alert(""foo""))'>";
            Assert.Equal(@"<div></div>", sanitizer.Sanitize(html), ignoreCase: true);
            html = @"<DIV STYLE='background-image: \000075
rl(javascript:alert(""foo""))'>";
            Assert.Equal(@"<div></div>", sanitizer.Sanitize(html), ignoreCase: true);
        }

        [Fact]
        public void SanitizeRemoveStylePhishingTest()
        {
            var sanitizer = Sanitizer;
            // The position property is not allowed
            var html = @"<div style=""position:absolute;top:0""></div>";
            Assert.Equal(@"<div style=""top: 0""></div>", sanitizer.Sanitize(html), ignoreCase: true);
            // Normal margins get passed through
            html = @"<div style=""margin:10px 20px""></div>";
            Assert.Equal(@"<div style=""margin: 10px 20px""></div>", sanitizer.Sanitize(html), ignoreCase: true);
        }

        [Fact]
        public void SanitizeRemoveSrcJavascriptTest()
        {
            var sanitizer = Sanitizer;
            var html = @"<img src=\'javascript:alert(""foo"")\'>";
            Assert.Equal(@"<img>", sanitizer.Sanitize(html), ignoreCase: true);
            // Case-insensitive protocol matching
            html = @"<IMG SRC=\'JaVaScRiPt:alert(""foo"")\'>";
            Assert.Equal(@"<img>", sanitizer.Sanitize(html), ignoreCase: true);
            // Grave accents (not parsed)
            // Protocol encoded using UTF-8 numeric entities
            html = @"<IMG SRC=\'&#106;&#97;&#118;&#97;&#115;&#99;&#114;&#105;&#112;&#116;&#58;alert(""foo"")\'>";
            Assert.Equal(@"<img>", sanitizer.Sanitize(html), ignoreCase: true);
            // Protocol encoded using UTF-8 numeric entities without a semicolon
            // (which is allowed because the max number of digits is used)
            html = @"<IMG SRC=\'&#0000106&#0000097&#0000118&#0000097&#0000115&#0000099&#0000114&#0000105&#0000112&#0000116&#0000058alert(""foo"")\'>";
            Assert.Equal(@"<img>", sanitizer.Sanitize(html), ignoreCase: true);
            // Protocol encoded using UTF-8 numeric hex entities without a semicolon
            // (which is allowed because the max number of digits is used)
            html = @"<IMG SRC=\'&#x6A&#x61&#x76&#x61&#x73&#x63&#x72&#x69&#x70&#x74&#x3A;alert(""foo"")\'>";
            Assert.Equal(@"<img>", sanitizer.Sanitize(html), ignoreCase: true);
            // Embedded tab character in protocol
            html = @"<IMG SRC=\'jav\tascript:alert(""foo"");\'>";
            Assert.Equal(@"<img>", sanitizer.Sanitize(html), ignoreCase: true);
            // Embedded tab character in protocol, but encoded this time
            html = @"<IMG SRC=\'jav&#x09;ascript:alert(""foo"");\'>";
            Assert.Equal(@"<img>", sanitizer.Sanitize(html), ignoreCase: true);
        }

        [Fact]
        public void SanitizeExpressionTest()
        {
            var sanitizer = Sanitizer;
            var html = @"<div style=""top:expression(alert())"">XSS</div>";
            Assert.Equal(@"<div>XSS</div>", sanitizer.Sanitize(html), ignoreCase: true);
        }

        [Fact]
        public void CapitalExpressionTest()
        {
            var sanitizer = Sanitizer;
            var html = @"<div style=""top:EXPRESSION(alert())"">XSS</div>";
            Assert.Equal(@"<div>XSS</div>", sanitizer.Sanitize(html), ignoreCase: true);
        }

        [Fact]
        public void SanitizeUrlWithJavascriptTest()
        {
            var sanitizer = Sanitizer;
            var html = @"<div style=""background-image:url(javascript:alert())"">XSS</div>";
            Assert.Equal(@"<div>XSS</div>", sanitizer.Sanitize(html), ignoreCase: true);
        }

        [Fact]
        public void SanitizeCapitalUrlWithJavascriptTest()
        {
            var sanitizer = Sanitizer;
            var html = @"<div style=""background-image:URL(javascript:alert())"">XSS</div>";
            Assert.Equal(@"<div>XSS</div>", sanitizer.Sanitize(html), ignoreCase: true);
        }

        [Fact]
        public void SanitizeUnicodeEscapesTest()
        {
            var sanitizer = Sanitizer;
            var html = @"<div style=""top:exp\72 ess\000069 on(alert())"">XSS</div>";
            Assert.Equal(@"<div>XSS</div>", sanitizer.Sanitize(html), ignoreCase: true);
        }

        [Fact]
        public void SanitizeBackslashWithoutHexTest()
        {
            var sanitizer = Sanitizer;
            var html = @"<div style=""top:e\xp\ression(alert())"">XSS</div>";
            Assert.Equal(@"<div>XSS</div>", sanitizer.Sanitize(html), ignoreCase: true);
            html = @"<div style=""top:e\\xp\\ression(alert())"">XSS</div>";
            Assert.Equal(@"<div>XSS</div>", sanitizer.Sanitize(html), ignoreCase: true);
        }

        [Fact]
        public void SanitizeUnsafePropsTest()
        {
            var sanitizer = Sanitizer;
            var html = @"<div style=""POSITION:RELATIVE"">XSS</div>";
            Assert.Equal(@"<div>XSS</div>", sanitizer.Sanitize(html), ignoreCase: true);

            html = @"<div style=""behavior:url(test.htc)"">XSS</div>";
            Assert.Equal(@"<div>XSS</div>", sanitizer.Sanitize(html), ignoreCase: true);

            html = @"<div style=""-ms-behavior:url(test.htc) url(#obj)"">XSS</div>";
            Assert.Equal(@"<div>XSS</div>", sanitizer.Sanitize(html), ignoreCase: true);

            html = @"<div style=""-o-link:'javascript:alert(1)';-o-link-source:current"">XSS</div>";
            Assert.Equal(@"<div>XSS</div>", sanitizer.Sanitize(html), ignoreCase: true);

            html = @"<div style=""-moz-binding:url(xss.xbl)"">XSS</div>";
            Assert.Equal(@"<div>XSS</div>", sanitizer.Sanitize(html), ignoreCase: true);
        }

        [Fact]
        public void SanitizeCssHackTest()
        {
            var sanitizer = Sanitizer;
            var html = @"<div style=""*position:static"">XSS</div>";
            Assert.Equal(@"<div>XSS</div>", sanitizer.Sanitize(html), ignoreCase: true);
        }

        [Fact]
        public void SanitizePropertyNameTest()
        {
            var sanitizer = Sanitizer;
            var html = @"<div style=""display:none;border-left-color:red;userDefined:1;-moz-user-selct:-moz-all"">prop</div>";
            Assert.Equal(@"<div style=""display: none; border-left-color: rgba(255, 0, 0, 1)"">prop</div>", sanitizer.Sanitize(html), ignoreCase: true);
        }

        [Fact]
        public void SanitizeUnicodeExpressionTest()
        {
            var sanitizer = Sanitizer;
            // Fullwidth small letters
            var html = @"<div style=""top:ｅｘｐｒｅｓｓｉｏｎ(alert())"">XSS</div>";
            Assert.Equal(@"<div>XSS</div>", sanitizer.Sanitize(html), ignoreCase: true);
            // Fullwidth capital letters
            html = @"<div style=""top:ＥＸＰＲＥＳＳＩＯＮ(alert())"">XSS</div>";
            Assert.Equal(@"<div>XSS</div>", sanitizer.Sanitize(html), ignoreCase: true);
            // IPA extensions
            html = @"<div style=""top:expʀessɪoɴ(alert())"">XSS</div>";
            Assert.Equal(@"<div>XSS</div>", sanitizer.Sanitize(html), ignoreCase: true);
        }

        [Fact]
        public void SanitizeUnicodeUrlTest()
        {
            var sanitizer = Sanitizer;
            // IPA extensions
            var html = @"<div style=""background-image:uʀʟ(javascript:alert())"">XSS</div>";
            Assert.Equal(@"<div>XSS</div>", sanitizer.Sanitize(html), ignoreCase: true);
        }

        [Fact]
        public void RemovingTagEventTest()
        {
            var sanitizer = new HtmlSanitizer();
            sanitizer.RemovingTag += (s, e) => e.Cancel = e.Tag.NodeName == "BLINK";
            var html = @"<div><script></script><blink>Test</blink></div>";
            Assert.Equal(@"<div><blink>Test</blink></div>", sanitizer.Sanitize(html), ignoreCase: true);
        }

        [Fact]
        public void RemovingAttributeEventTest()
        {
            var sanitizer = new HtmlSanitizer();
            sanitizer.RemovingAttribute += (s, e) => e.Cancel = e.Attribute.Name == "onclick";
            var html = @"<div alt=""alt"" onclick=""test"" onload=""test""></div>";
            Assert.Equal(@"<div alt=""alt"" onclick=""test""></div>", sanitizer.Sanitize(html), ignoreCase: true);
        }

        [Fact]
        public void RemovingAttributeEventTagTest()
        {
            var sanitizer = new HtmlSanitizer();
            sanitizer.RemovingAttribute += (s, e) => Assert.IsAssignableFrom<IHtmlDivElement>(e.Tag);
            var html = @"<div alt=""alt"" onclick=""test"" onload=""test""></div>";
            sanitizer.Sanitize(html);
        }

        [Fact]
        public void RemovingStyleEventTest()
        {
            var sanitizer = new HtmlSanitizer();
            sanitizer.RemovingStyle += (s, e) => e.Cancel = e.Style.Name == "column-count";
            var html = @"<div style=""top: 1px; column-count: 3;""></div>";
            Assert.Equal(@"<div style=""top: 1px; column-count: 3""></div>", sanitizer.Sanitize(html), ignoreCase: true);
        }

        [Fact]
        public void RemovingStyleEventTagTest()
        {
            var sanitizer = new HtmlSanitizer();
            sanitizer.RemovingStyle += (s, e) => Assert.IsAssignableFrom<IHtmlDivElement>(e.Tag);
            var html = @"<div style=""background: 0; test: xyz; bad: bad;""></div>";
            sanitizer.Sanitize(html);
        }

        [Fact]
        public void ProtocolRelativeTest()
        {
            var sanitizer = Sanitizer;
            var html = @"<a href=""//www.example.com/test"">Test</a>";
            Assert.Equal(@"<a href=""//www.example.com/test"">Test</a>", sanitizer.Sanitize(html), ignoreCase: true);
            Assert.Equal(@"<a href=""https://www.example.com/test"">Test</a>", sanitizer.Sanitize(html, baseUrl: @"https://www.xyz.com/123"), ignoreCase: true);
        }

        [Fact]
        public void JavaScriptIncludeAndAngleBracketsTest()
        {
            // Arrange
            var sanitizer = Sanitizer;

            // Act
            string htmlFragment = "<BR SIZE=\"&{alert('XSS&gt;')}\">";
            string actual = sanitizer.Sanitize(htmlFragment);

            // Assert
            string expected = "<BR>";
            Assert.Equal(expected, actual, ignoreCase: true);
        }

        [Fact]
        public void AllowDataAttributesTest()
        {
            var sanitizer = new HtmlSanitizer()
            {
                AllowDataAttributes = true
            };
            var html = @"<div data-test1=""value x""></div>";
            Assert.Equal(html, sanitizer.Sanitize(html), ignoreCase: true);
        }

        [Fact]
        public void AllowDataAttributesCaseTest()
        {
            var sanitizer = new HtmlSanitizer()
            {
                AllowDataAttributes = true
            };
            var html = @"<div DAta-test1=""value x""></div>";
            Assert.Equal(html, sanitizer.Sanitize(html), ignoreCase: true);
        }

        [Fact]
        public void AllowDataAttributesOffTest()
        {
            var sanitizer = new HtmlSanitizer()
            {
                AllowDataAttributes = false
            };
            var html = @"<div data-test1=""value x""></div>";
            Assert.Equal(@"<div></div>", sanitizer.Sanitize(html), ignoreCase: true);
        }

        [Fact]
        public void SanitizeNonClosedTagTest()
        {
            var sanitizer = Sanitizer;
            var html = @"<div>Hallo <p><b>Bold<br>Ballo";
            Assert.Equal(@"<div>Hallo <p><b>Bold<br>Ballo</b></p></div>", sanitizer.Sanitize(html), ignoreCase: true);
        }

        [Fact]
        public void PostProcessNodeTest()
        {
            var sanitizer = new HtmlSanitizer();
            sanitizer.PostProcessNode += (s, e) =>
            {
                if (e.Node is IHtmlElement el)
                {
                    el.ClassList.Add("test");
                    var b = e.Document.CreateElement("b");
                    b.TextContent = "Test";
                    el.AppendChild(b);
                }
            };
            var html = @"<div>Hallo</div>";
            var sanitized = sanitizer.Sanitize(html);
            Assert.Equal(@"<div class=""test"">Hallo<b>Test</b></div>", sanitized, ignoreCase: true);
        }

        [Fact]
        public void PostProcessNodeTestUsingDocument()
        {
            var sanitizer = new HtmlSanitizer();
            sanitizer.PostProcessNode += (s, e) =>
            {
                if (e.Node is IHtmlDivElement el)
                {
                    el.ClassList.Add("test");
                    var b = e.Document.CreateElement("b");
                    b.TextContent = "Test";
                    el.AppendChild(b);
                }
            };
            var html = @"<html><head></head><body><div>Hallo</div></body></html>";
            var sanitized = sanitizer.SanitizeDocument(html);
            Assert.Equal(@"<html><head></head><body><div class=""test"">Hallo<b>Test</b></div></body></html>", sanitized, ignoreCase: true);
        }

        [Fact]
        public void PostProcessDomTest()
        {
            var sanitizer = new HtmlSanitizer();
            sanitizer.PostProcessDom += (s, e) =>
            {
                var p = e.Document.CreateElement("p");
                p.TextContent = "World";
                e.Document.Body.AppendChild(p);
            };

            var html = @"<div>Hallo</div>";
            var sanitized = sanitizer.Sanitize(html);
            Assert.Equal(@"<div>Hallo</div><p>World</p>", sanitized, ignoreCase: true);
        }

        [Fact]
        public void AutoLinkTest()
        {
            var sanitizer = new HtmlSanitizer();
            sanitizer.PostProcessNode += (s, e) =>
            {
                if (e.Node is IText text)
                {
                    var autolinked = Regex.Replace(text.NodeValue, @"https?://[^\s]+[^\s!?.:;,]+", m => $@"<a href=""{m.Value}"">{m.Value}</a>", RegexOptions.IgnoreCase);
                    if (autolinked != text.NodeValue)
                    {
                        var f = new HtmlParser().ParseDocument(autolinked);
                        foreach (var node in f.Body.ChildNodes)
                            e.ReplacementNodes.Add(node);
                    }
                }
            };
            var html = @"<div>Click here: http://example.com/.</div>";
            Assert.Equal(@"<div>Click here: <a href=""http://example.com/"">http://example.com/</a>.</div>", sanitizer.Sanitize(html), ignoreCase: true);
            Assert.Equal(@"Check out <a href=""https://www.google.com"">https://www.google.com</a>.", sanitizer.Sanitize("Check out https://www.google.com."), ignoreCase: true);
        }

        [Fact]
        public void RussianTextTest()
        {
            // Arrange
            var s = Sanitizer;

            // Act
            var htmlFragment = "Тест";
            var actual = s.Sanitize(htmlFragment, "");

            // Assert
            var expected = htmlFragment;
            Assert.Equal(expected, actual, ignoreCase: true);
        }

        [Fact]
        public void DisallowCssPropertyValueTest()
        {
            // Arrange
            var s = new HtmlSanitizer { DisallowCssPropertyValue = new Regex(@"^rgba\(0.*") };

            // Act
            var htmlFragment = @"<div style=""color: rgba(0, 0, 0, 1); background-color: rgba(255, 255, 255, 1)"">Test</div>";
            var actual = s.Sanitize(htmlFragment);

            // Assert
            var expected = @"<div style=""background-color: rgba(255, 255, 255, 1)"">Test</div>";
            Assert.Equal(expected, actual, ignoreCase: true);
        }

        [Fact]
        public void CssKeyTest()
        {
            // Arrange
            var s = Sanitizer;

            // Act
            var htmlFragment = @"<div style=""\000062ackground-image: URL(http://www.example.com/bg.jpg)"">Test</div>";
            var actual = s.Sanitize(htmlFragment);

            // Assert
            var expected = @"<div style=""background-image: url(&quot;http://www.example.com/bg.jpg&quot;)"">Test</div>";
            Assert.Equal(expected, actual, ignoreCase: true);
        }

        [Fact]
        public void InvalidBaseUrlTest()
        {
            // Arrange
            var s = Sanitizer;

            // Act
            var htmlFragment = @"<div style=""color: rgba(0, 0, 0, 1); background-image: URL(x/y/bg.jpg)"">Test</div>";
            var actual = s.Sanitize(htmlFragment, "hallo");

            // Assert
            var expected = @"<div style=""color: rgba(0, 0, 0, 1)"">Test</div>";
            Assert.Equal(expected, actual, ignoreCase: true);
        }

        [Fact]
        public void XhtmlTest()
        {
            // Arrange
            var s = Sanitizer;

            // Act
            var htmlFragment = @"<div><img src=""xyz""><br></div>";
            var actual = s.Sanitize(htmlFragment, "", AngleSharp.Xml.XmlMarkupFormatter.Instance);

            // Assert
            var expected = @"<div><img src=""xyz"" /><br /></div>";
            Assert.Equal(expected, actual, ignoreCase: true);
        }

        [Fact]
        public void MultipleRecipientsTest()
        {
            // https://github.com/mganss/HtmlSanitizer/issues/41

            // Arrange
            var s = new HtmlSanitizer();
            s.AllowedSchemes.Add("mailto");

            // Act
            var htmlFragment = @"<a href=""mailto:bonnie@example.com,clyde@example.com"">Bang Bang</a>";
            var actual = s.Sanitize(htmlFragment);

            // Assert
            var expected = htmlFragment;
            Assert.Equal(expected, actual, ignoreCase: true);
        }

        [Fact]
        public void QuotedBackgroundImageTest()
        {
            // https://github.com/mganss/HtmlSanitizer/issues/44

            // Arrange
            var s = Sanitizer;

            // Act
            var htmlFragment = "<div style=\"background-image: url('some/random/url.img')\"></div>";
            var actual = s.Sanitize(htmlFragment);

            // Assert
            var expected = "<div style=\"background-image: url(&quot;some/random/url.img&quot;)\"></div>";
            Assert.Equal(expected, actual, ignoreCase: true);
        }

        [Fact]
        public void QuotedBackgroundImageFromIE9()
        {
            // Arrange
            var s = Sanitizer;

            // Act
            var htmlFragment = "<span style='background-image: url(\"/api/users/defaultAvatar\");'></span>";
            var actual = s.Sanitize(htmlFragment);

            // Assert
            var expected = "<span style=\"background-image: url(&quot;/api/users/defaultAvatar&quot;)\"></span>";
            Assert.Equal(expected, actual, ignoreCase: true);
        }

        [Fact]
        public void RemoveEventForNotAllowedTag()
        {
            var allowedTags = new[] {"a"};
            RemoveReason? actual = null;

            var s = new HtmlSanitizer(allowedTags);
            s.RemovingTag += (sender, args) =>
            {
                actual = args.Reason;
            };

            s.Sanitize("<span>just any content</span>");

            Assert.Equal(RemoveReason.NotAllowedTag, actual);
        }

        [Fact]
        public void RemoveEventForNotAllowedAttribute()
        {
            var allowedTags = new[] { "a" };
            var allowedAttributes = new[] {"id"};
            RemoveReason? actual = null;

            var s = new HtmlSanitizer(allowedTags: allowedTags, allowedAttributes: allowedAttributes);
            s.RemovingAttribute += (sender, args) =>
            {
                actual = args.Reason;
            };

            s.Sanitize("<a href=\"http://www.example.com\">just any content</a>");

            Assert.Equal(RemoveReason.NotAllowedAttribute, actual);
        }

        [Fact]
        public void RemoveEventForNotAllowedStyle()
        {
            var allowedTags = new[] { "a" };
            var allowedAttributes = new[] { "style" };
            var allowedStyles = new[] { "margin" };
            RemoveReason? actual = null;

            var s = new HtmlSanitizer(allowedTags: allowedTags, allowedAttributes: allowedAttributes, allowedCssProperties: allowedStyles);
            s.RemovingStyle += (sender, args) =>
            {
                actual = args.Reason;
            };

            s.Sanitize("<a style=\"padding:5px\">just any content</a>");

            Assert.Equal(RemoveReason.NotAllowedStyle, actual);
        }

        [Fact]
        public void RemoveEventForNotAllowedValueAtAttribute()
        {
            var allowedTags = new[] { "a" };
            var allowedAttributes = new[] { "id" };
            RemoveReason? actual = null;

            var s = new HtmlSanitizer(allowedTags: allowedTags, allowedAttributes: allowedAttributes);
            s.RemovingAttribute += (sender, args) =>
            {
                actual = args.Reason;
            };

            s.Sanitize("<a id=\"anyId&{\">just any content</a>");

            Assert.Equal(RemoveReason.NotAllowedValue, actual);
        }

        [Fact]
        public void RemoveEventForNotAllowedValueAtStyle()
        {
            var allowedTags = new[] { "a" };
            var allowedAttributes = new[] { "style" };
            var allowedStyles = new[] { "margin-top" };
            RemoveReason? actual = null;

            var s = new HtmlSanitizer(allowedTags: allowedTags, allowedAttributes: allowedAttributes, allowedCssProperties: allowedStyles)
            {
                DisallowCssPropertyValue = new Regex(@"\d+.*")
            };
            s.RemovingStyle += (sender, args) =>
            {
                actual = args.Reason;
            };

            s.Sanitize("<a style=\"margin-top:17px\">just any content</a>");

            Assert.Equal(RemoveReason.NotAllowedValue, actual);
        }

        [Fact]
        public void RemoveEventForNotAllowedUrlAtUriAttribute()
        {
            var allowedTags = new[] { "a" };
            var allowedAttributes = new[] { "href" };
            var uriAttributes = new[] { "href" };
            RemoveReason? actual = null;

            var s = new HtmlSanitizer(allowedTags: allowedTags, allowedAttributes: allowedAttributes, uriAttributes: uriAttributes);
            s.RemovingAttribute += (sender, args) =>
            {
                actual = args.Reason;
            };

            s.Sanitize("<a href=\"javascript:(alert('xss'))\">just any content</a>");

            Assert.Equal(RemoveReason.NotAllowedUrlValue, actual);
        }

        [Fact]
        public void RemoveEventForNotAllowedUrlAtStyle()
        {
            var allowedTags = new[] { "a" };
            var allowedAttributes = new[] { "style" };
            var allowedStyles = new[] { "background-image" };
            RemoveReason? actual = null;

            var s = new HtmlSanitizer(allowedTags: allowedTags, allowedAttributes: allowedAttributes, allowedCssProperties: allowedStyles);
            s.RemovingStyle += (sender, args) =>
            {
                actual = args.Reason;
            };

            var h = s.Sanitize("<a style=\"background-image:url(javascript:alert('xss'))\">just any content</a>");

            Assert.Equal(RemoveReason.NotAllowedUrlValue, actual);
        }

        [Fact]
        public void RemoveEventForNotAllowedTag_ScriptTag()
        {
            RemoveReason? actual = null;
            var s = new HtmlSanitizer();
            s.RemovingTag += (sender, args) =>
            {
                actual = args.Reason;
            };
            s.Sanitize("<script>alert('Hello world!')</script>");
            Assert.Equal(RemoveReason.NotAllowedTag, actual);
        }

        [Fact]
        public void RemoveEventForNotAllowedTag_StyleTag()
        {
            RemoveReason? actual = null;
            var s = new HtmlSanitizer();
            s.RemovingTag += (sender, args) =>
            {
                actual = args.Reason;
            };
            s.Sanitize("<style> body {background-color:lightgrey;}</style>");
            Assert.Equal(RemoveReason.NotAllowedTag, actual);
        }

        [Fact]
        public void RemoveEventForNotAllowedTag_ScriptTagAndSpan()
        {
            RemoveReason? actual = null;
            var s = new HtmlSanitizer();
            s.RemovingTag += (sender, args) =>
            {
                actual = args.Reason;
            };
            s.Sanitize("<span>Hi</span><script>alert('Hello world!')</script>");
            Assert.Equal(RemoveReason.NotAllowedTag, actual);
        }

        [Fact]
        public void RemoveEventForNotAllowedCssClass()
        {
            RemoveReason? reason = null;
            string removedClass = null;

            var s = new HtmlSanitizer(allowedAttributes: new[] { "class" }) { AllowedClasses = { "good" } };
            s.RemovingCssClass += (sender, args) =>
            {
                reason = args.Reason;
                removedClass = args.CssClass;
            };

            s.Sanitize(@"<div class=""good bad"">Test</div>");

            Assert.Equal("bad", removedClass);
            Assert.Equal(RemoveReason.NotAllowedCssClass, reason);
        }

        [Fact]
        public void RemoveEventForEmptyClassAttributeAfterClassRemoval()
        {
            RemoveReason? reason = null;
            string attributeName = null;

            var s = new HtmlSanitizer(allowedAttributes: new[] { "class" }) { AllowedClasses = { "other" } };
            s.RemovingAttribute += (sender, args) =>
            {
                attributeName = args.Attribute.Name;
                reason = args.Reason;
            };

            s.Sanitize(@"<div class=""good bad"">Test</div>");

            Assert.Equal("class", attributeName);
            Assert.Equal(RemoveReason.ClassAttributeEmpty, reason);
        }

        [Fact]
        public void DocumentTest()
        {
            var s = new HtmlSanitizer();
            s.AllowedTags.Add("title");
            var html = "<html><head><title>Test</title></head><body><div>Test</div></body></html>";

            var actual = s.SanitizeDocument(html);

            Assert.Equal(html, actual);
        }

        [Fact]
        public void DocumentFromFragmentTest()
        {
            var s = Sanitizer;
            var html = "<div>Test</div>";

            var actual = s.SanitizeDocument(html);

            Assert.Equal("<html><head></head><body><div>Test</div></body></html>", actual);
        }

        [Fact]
        public void FragmentFromDocumentTest()
        {
            var s = Sanitizer;
            var html = "<html><head><title>Test</title></head><body><div>Test</div></body></html>";

            var actual = s.Sanitize(html);

            Assert.Equal("<div>Test</div>", actual);
        }

        [Fact]
        public void StyleTagTest()
        {
            var s = new HtmlSanitizer();
            s.AllowedTags.Add("style");
            var html = "<html><head><style>body { background-color: rgba(255, 255, 255, 1); hallo-ballo: xyz }</style></head><body><div>Test</div></body></html>";

            var actual = s.SanitizeDocument(html);

            Assert.Equal("<html><head><style>body { background-color: rgba(255, 255, 255, 1) }</style></head><body><div>Test</div></body></html>", actual);
        }

        [Fact]
        public void StyleAtTest()
        {
            var s = new HtmlSanitizer();
            s.AllowedTags.Add("style");
            s.AllowedAtRules.Add(AngleSharp.Css.Dom.CssRuleType.Media);
            s.AllowedAtRules.Add(AngleSharp.Css.Dom.CssRuleType.Keyframes);
            s.AllowedAtRules.Add(AngleSharp.Css.Dom.CssRuleType.Keyframe);
            s.AllowedAtRules.Add(AngleSharp.Css.Dom.CssRuleType.Page);
            var html = @"<html><head><style>
@charset ""UTF-8"";
@import url(evil.css);
@namespace url(http://www.w3.org/1999/xhtml);
@namespace svg url(http://www.w3.org/2000/svg);
@media (min-width: 100px) {
    div { color: rgba(0, 0, 0, 1); }
    @font-face { font-family: test }
}
@supports (--foo: green) {
  body {
    color: green;
  }
  @media (min-width: 200px) {
    body { color: red; }
  }
}
@document url(http://www.w3.org/),
               url-prefix(http://www.w3.org/Style/),
               domain(mozilla.org),
               regexp(""https:.* "")
{
    body {
        color: purple;
        background: yellow;
    }
}
@page { size:8.5in 11in; margin-top: 2cm }
@font-face {
      font-family: ""Bitstream Vera Serif Bold""
      src: url(""https://mdn.mozillademos.org/files/2468/VeraSeBd.ttf"");
      color: rgba(0, 0, 0, 1);
}
@keyframes identifier {
  0% { top: 0; }
  50% { top: 30px; left: 20px; }
  50% { top: 10px; }
  100% { top: 0; background-image: url('javascript:alert(xss)') }
}
@viewport {
  min-width: 640px;
  max-width: 800px;
}
@counter-style winners-list {
  system: fixed;
  symbols: url(gold-medal.svg) url(silver-medal.svg) url(bronze-medal.svg);
  suffix: "" "";
}
@font-feature-values Font One { /* How to activate nice-style in Font One */
  @styleset {
    nice-style: 12;
  }
}
</style></head></html>";

            var actual = s.SanitizeDocument(html);

            Assert.Equal(@"<html><head><style>@namespace url(""http://www.w3.org/1999/xhtml"");
@namespace svg url(""http://www.w3.org/2000/svg"");
@media (min-width: 100px) { div { color: rgba(0, 0, 0, 1) } }
@page { margin-top: 2cm }
@keyframes identifier { 0% { top: 0 } 50% { top: 30px; left: 20px } 50% { top: 10px } 100% { top: 0 } }</style></head><body></body></html>".Replace("\r\n", "\n"),
                actual);
        }

        [Fact]
        public void DataTest()
        {
            // https://github.com/mganss/HtmlSanitizer/issues/66

            var sanitizer = new HtmlSanitizer()
            {
                AllowDataAttributes = true
            };
            sanitizer.AllowedSchemes.Add("data");
            var html = @"    <p>
        <img src=""data:image/jpeg;base64,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"">
    </p>
".Replace("\r\n", "\n");

            var actual = sanitizer.Sanitize(html);

            Assert.Equal(html, actual);
        }

        [Fact]
        public void UriHashTest()
        {
            var s = Sanitizer;
            var html = @"<a href=""http://domain.com/index.html?test=#value#"">test</a>";

            var actual = s.Sanitize(html);

            Assert.Equal(html, actual);
        }

        [Fact]
        public void FragmentTest()
        {
            var s = Sanitizer;
            var html = @"<script>alert('test');</script><p>Test</p>";

            var actual = s.Sanitize(html);

            Assert.Equal("<p>Test</p>", actual);
        }

        [Fact]
        public void OpenTagFragmentTest()
        {
            // https://github.com/mganss/HtmlSanitizer/issues/75

            var s = Sanitizer;
            var html = "<p>abc<script>xyz</p>";

            var actual = s.Sanitize(html);

            Assert.Equal("<p>abc</p>", actual);
        }

        [Fact]
        public void NullStyleTest()
        {
            // https://github.com/mganss/HtmlSanitizer/issues/81

            var s = new HtmlSanitizer { HtmlParserFactory = () => new HtmlParser(new HtmlParserOptions(), BrowsingContext.New(new Configuration())) };
            var html = @"<p style=""t"">xyz</p>";

            var actual = s.Sanitize(html);

            Assert.Equal("<p>xyz</p>", actual);
        }

        [Fact]
        public void EscapeEntityInAttributeValueTest()
        {
            // https://github.com/mganss/HtmlSanitizer/issues/84

            var s = new HtmlSanitizer { HtmlParserFactory = () => new HtmlParser(new HtmlParserOptions(), BrowsingContext.New(new Configuration())) };
            var html = @"<input type=""text"" name=""my_name"" value=""<insert name>"">";

            var actual = s.Sanitize(html);

            Assert.Equal(@"<input type=""text"" name=""my_name"" value=""&lt;insert name&gt;"">", actual);
        }

        [Fact]
        public void FontFaceTest()
        {
            // https://github.com/mganss/HtmlSanitizer/issues/80

            var s = new HtmlSanitizer()
            {
                AllowDataAttributes = true
            };
            s.AllowedAtRules.Add(CssRuleType.FontFace);

            s.AllowedTags.Add("style");

            s.AllowedCssProperties.Add("src");
            s.AllowedCssProperties.Add("font-family");

            var html = @"<html><head><style>@font-face { font-family: FrutigerLTStd; src: url(""https://example.com/FrutigerLTStd-Light.otf"") format(""opentype"") }</style></head><body></body></html>";
            var actual = s.SanitizeDocument(html);

            Assert.Equal(html, actual);
        }

        public static IEnumerable<T> Shuffle<T>(IEnumerable<T> source, Random rng)
        {
            T[] elements = source.ToArray();
            for (int i = elements.Length - 1; i >= 0; i--)
            {
                // Swap element "i" with a random earlier element it (or itself)
                // ... except we don't really need to swap it fully, as we can
                // return it immediately, and afterwards it's irrelevant.
                int swapIndex = rng.Next(i + 1);
                yield return elements[swapIndex];
                elements[swapIndex] = elements[i];
            }
        }

        [Fact]
        public void ThreadTest()
        {
            const int numThreads = 16;
            const int numRuns = 1000;
            var random = new Random(615322944);

            for (int i = 0; i < numRuns; i++)
            {
                var allGo = new ManualResetEvent(false);
                Exception firstException = null;
                var failures = 0;
                var fixture = new HtmlSanitizerFixture();
                var tests = new HtmlSanitizerTests(fixture);
                var waiting = numThreads;
                var methods = typeof(HtmlSanitizerTests).GetTypeInfo().GetMethods()
                    .Where(m => m.GetCustomAttributes(typeof(Xunit.FactAttribute), false).Any())
                    .Where(m => m.Name != "ThreadTest");
                var threads = Shuffle(methods, random)
                    .Take(numThreads)
                    .Select(m => new Thread(() =>
                    {
                        try
                        {
                            if (Interlocked.Decrement(ref waiting) == 0) allGo.Set();
                            m.Invoke(tests, null);
                        }
#pragma warning disable CA1031 // Do not catch general exception types
                        catch (Exception ex)
                        {
                            Interlocked.CompareExchange(ref firstException, ex, null);
                            Interlocked.Increment(ref failures);
                        }
#pragma warning restore CA1031 // Do not catch general exception types
                    })).ToList();

                foreach (var thread in threads)
                    thread.Start();
                foreach (var thread in threads)
                    thread.Join();

                Assert.Null(firstException);
                Assert.Equal(0, failures);
            }
        }

        [Fact]
        public void AllowAllClassesByDefaultTest()
        {
            var sanitizer = new HtmlSanitizer(allowedAttributes: new[] { "class" });

            var html = @"<div class=""good bad"">Test</div>";
            var actual = sanitizer.Sanitize(html);

            Assert.Equal(@"<div class=""good bad"">Test</div>", actual);
        }

        [Fact]
        public void AllowClassesTest()
        {
            var sanitizer = new HtmlSanitizer(allowedAttributes: new[] { "class" }) { AllowedClasses = { "good" } };

            var html = @"<div class=""good bad"">Test</div>";
            var actual = sanitizer.Sanitize(html);

            Assert.Equal(@"<div class=""good"">Test</div>", actual);
        }

        [Fact]
        public void AllowClassesUsingEventTest()
        {
            var sanitizer = new HtmlSanitizer();
            sanitizer.RemovingAttribute += (s, e) =>
            {
                if (e.Attribute.Name == "class")
                {
                    e.Tag.ClassList.Remove(e.Tag.ClassList.Except(new[] { "good", "oktoo" }, StringComparer.OrdinalIgnoreCase).ToArray());
                    e.Cancel = e.Tag.ClassList.Any();
                }
            };

            var html = @"<div class=""good bad"">Test</div>";
            var actual = sanitizer.Sanitize(html);

            Assert.Equal(@"<div class=""good"">Test</div>", actual);
        }

        [Fact]
        public void RemoveClassAttributeIfEmptyTest()
        {
            var sanitizer = new HtmlSanitizer(allowedAttributes: new[] { "class" }) { AllowedClasses = { "other" } };

            var html = @"<div class=""good bad"">Test</div>";
            var actual = sanitizer.Sanitize(html);

            Assert.Equal(@"<div>Test</div>", actual);
        }

        [Fact]
        public void TextTest()
        {
            var sanitizer = new HtmlSanitizer();
            sanitizer.AllowedTags.Remove("div");
            sanitizer.RemovingTag += (s, e) =>
            {
                if (e.Tag.HasChildNodes)
                {
                    e.Tag.Replace(e.Tag.ChildNodes.ToArray());
                    e.Cancel = true;
                }
            };

            var html = @"Test1 <div>Test2 <script>Test3</script> <b>Test4</b></div>";
            var actual = sanitizer.Sanitize(html);

            Assert.Equal("Test1 Test2 Test3 <b>Test4</b>", actual);
        }

        [Fact]
        public void KeepChildNodesTest()
        {
            var sanitizer = new HtmlSanitizer { KeepChildNodes = true };
            sanitizer.AllowedTags.Remove("div");

            var html = @"Test1 <div>Test2 <script>Test3</script> <b>Test4</b></div>";
            var actual = sanitizer.Sanitize(html);

            Assert.Equal("Test1 Test2 Test3 <b>Test4</b>", actual);
        }

        [Fact]
        public void NormalizeTest()
        {
            var sanitizer = new HtmlSanitizer();
            sanitizer.PostProcessNode += (s, e) =>
            {
                Assert.Single(e.Document.Body.ChildNodes);
                var text = e.Node as IText;
                Assert.NotNull(text);
                Assert.Equal("Test1Test2", text.NodeValue);
            };

            var html = @"Test1<script>test();</script>Test2<!-- comment -->";

            var actual = sanitizer.Sanitize(html);

            Assert.Equal("Test1Test2", actual);
        }

        [Fact]
        public void RemovingCommentTest()
        {
            var sanitizer = new HtmlSanitizer();
            sanitizer.RemovingComment += (s, e) => e.Cancel = e.Comment.TextContent.Contains("good comment");

            var html = @"<!-- bad comment --><!-- good comment -->";

            var actual = sanitizer.Sanitize(html);

            Assert.Equal("<!-- good comment -->", actual);
        }

        [Fact]
        public void TrailingSlashTest()
        {
            var sanitizer = new HtmlSanitizer();
            sanitizer.AllowedSchemes.Add("resources");

            var html = "<IMG src=\"resources://ais_w20_h20_33ba129c.png\">";

            var actual = sanitizer.Sanitize(html);

            Assert.Equal(html, actual, ignoreCase: true);
        }

        [Fact]
        public void FileUrlTest()
        {
            var sanitizer = new HtmlSanitizer();
            sanitizer.AllowedSchemes.Add("file");

            var html = @"<a href=""file:///C:/exampleㄓ.txt"">test</a>";

            var actual = sanitizer.Sanitize(html);

            Assert.Equal(html, actual);
        }

        [Fact]
        public void SvgTest()
        {
            // https://github.com/mganss/HtmlSanitizer/issues/119

            var sanitizer = new HtmlSanitizer();
            sanitizer.AllowedTags.Add("svg");

            var html = @"<svg onchange='alert(1)'>123</svg>";

            var actual = sanitizer.Sanitize(html);

            Assert.Equal("<svg>123</svg>", actual);
        }

        [Fact]
        public void SquareBracketTest()
        {
            // https://github.com/mganss/HtmlSanitizer/issues/137

            var sanitizer = new HtmlSanitizer();
            sanitizer.AllowedAttributes.Add("[minutes]");

            var html = @"<div [minutes]=""2"">123</div>";

            var actual = sanitizer.Sanitize(html);

            Assert.Equal(html, actual);
        }

        [Fact]
        public void FilterUrlTest()
        {
            // https://github.com/mganss/HtmlSanitizer/issues/156

            var sanitizer = new HtmlSanitizer();
            sanitizer.FilterUrl += (s, e) => e.SanitizedUrl = "https://www.example.com/test.png";

            var html = @"<img src=""http://www.example.com/"">";

            var actual = sanitizer.Sanitize(html);

            Assert.Equal(@"<img src=""https://www.example.com/test.png"">", actual);
        }


        [Fact]
        public void EncodingTest()
        {
            // https://github.com/mganss/HtmlSanitizer/issues/158

            var sanitizer = new HtmlSanitizer();
            sanitizer.AllowedTags.Add("meta");
            sanitizer.AllowedAttributes.Add("http-equiv");
            sanitizer.AllowedAttributes.Add("content");

            var html = @"<html><head><meta http-equiv=""Content-Type"" content=""text/html; charset=iso-8859-1""></head><body>kopieën</body></html>";

            using (var stream = new MemoryStream(Encoding.GetEncoding("iso-8859-1").GetBytes(html)))
            {
                var actual = sanitizer.SanitizeDocument(stream);

                Assert.Equal(html, actual);
            }
        }

        [Fact]
        public void RemovingFramesetShouldTriggerEventTest()
        {
            // https://github.com/mganss/HtmlSanitizer/issues/163

            var sanitizer = new HtmlSanitizer();
            bool anyNodeRemoved = false;
            sanitizer.RemovingTag += (s, e) => anyNodeRemoved = true;
            var html = @"<html><frameset><frame src=""javascript:alert(1)""></frame></frameset></html>";
            var actual = sanitizer.SanitizeDocument(html);
            Assert.True(anyNodeRemoved);
            Assert.Equal("<html><head></head></html>", actual);
        }

        [Fact]
        public void HtmlDocumentTest()
        {
            // https://github.com/mganss/HtmlSanitizer/issues/164

            var sanitizer = new HtmlSanitizer();
            var html = @"<html onmousemove=""alert(document.location)""><head></head><body></body></html>";

            var actual = sanitizer.SanitizeDocument(html);

            Assert.Equal("<html><head></head><body></body></html>", actual);
        }

        [Fact]
        public void PreParsedDocumentWithoutContextTest()
        {
            // parse a document before calling SantizeDom
            var sanitizer = new HtmlSanitizer();
            var parser = new HtmlParser(new HtmlParserOptions(), BrowsingContext.New(new Configuration().WithCss(new CssParserOptions
            {
                IsIncludingUnknownDeclarations = true,
                IsIncludingUnknownRules = true,
                IsToleratingInvalidSelectors = true,
            })));
            var html = @"<html><head></head><body><div>hi</div></body></html>";

            var document = parser.ParseDocument(html);
            var returnedDocument = sanitizer.SanitizeDom(document);

            Assert.Equal("<html><head></head><body><div>hi</div></body></html>", returnedDocument.ToHtml());
        }

        [Fact]
        public void PreParsedDocumentWithContextTest()
        {
            // parse a document before calling SantizeDom
            var sanitizer = new HtmlSanitizer();
            var parser = new HtmlParser(new HtmlParserOptions(), BrowsingContext.New(new Configuration().WithCss(new CssParserOptions
            {
                IsIncludingUnknownDeclarations = true,
                IsIncludingUnknownRules = true,
                IsToleratingInvalidSelectors = true,
            })));
            var html = @"<html><head></head><body><div>hi</div></body></html>";

            var document = parser.ParseDocument(html);
            var returnedDocument = sanitizer.SanitizeDom(document, document.Body);

            Assert.Equal("<html><head></head><body><div>hi</div></body></html>", returnedDocument.ToHtml());
        }

        [Fact]
        public void StyleByPassTest()
        {
            var sanitizer = new HtmlSanitizer();

            sanitizer.AllowedTags.Add("style");

            var html = "aaabc<style>x[x='\\3c /style>\\3c img src onerror=alert(1)>']{}</style>";
            var sanitized = sanitizer.Sanitize(html, "http://www.example.com");

            Assert.Equal("aaabc<style>x[x=\"\\3c/style>\\3cimg src onerror=alert(1)>\"] { }</style>", sanitized);
        }
    }
}

#pragma warning restore 1591
